"""Defensive readers for the pcap and pcapng capture container formats.

Why not dpkt's readers? Two reasons, both found while auditing Phase 1:

* dpkt's pcapng reader only honours the *first* Interface Description Block, so
  a capture taken with ``dumpcap -i eth0 -i lo`` (Ethernet + loopback) decodes
  every loopback frame as Ethernet garbage.
* dpkt's pcap reader trusts the per-record ``caplen`` field and reads that many
  bytes. One crafted record header (``caplen = 0xFFFFFFFF``) turns the rest
  of a stream, up to 4 GiB, into a single in-memory frame.

The capture file is untrusted input. Every length field is validated against
:data:`MAX_RECORD_BYTES` *before* anything is read, so a hostile length cannot
exhaust memory. A truncated final record (``tcpdump`` killed mid-write, a copy
interrupted) is normal in practice: it ends the stream cleanly and is reported
through :class:`CaptureInfo.truncated` instead of raising. Structural
corruption in the middle of a file raises :class:`CaptureFormatError`.

pcapng support follows the format draft
(https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-02.html):
Section Header Blocks set the byte order and reset interfaces; Interface
Description Blocks carry the link type, ``if_tsresol`` and ``if_tsoffset``;
Enhanced, Simple and obsolete Packet Blocks yield frames; all other block types
are skipped and counted.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Protocol

#: Upper bound for one captured frame or pcapng block. 16 MiB is far above the
#: largest real snaplen (262 144 bytes) and still small enough to be harmless.
MAX_RECORD_BYTES = 16 * 1024 * 1024

# Classic pcap magic numbers -> (byte order, timestamp fraction divisor).
PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e6),
    b"\xa1\xb2\xc3\xd4": (">", 1e6),
    b"\x4d\x3c\xb2\xa1": ("<", 1e9),
    b"\xa1\xb2\x3c\x4d": (">", 1e9),
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

# pcapng block types and options.
SHB = 0x0A0D0D0A
IDB = 0x00000001
PB = 0x00000002  # obsolete, still written by some old tools
SPB = 0x00000003
EPB = 0x00000006
BYTE_ORDER_MAGIC = 0x1A2B3C4D
OPT_ENDOFOPT = 0
OPT_IF_TSRESOL = 9
OPT_IF_TSOFFSET = 14

Frame = tuple[float, bytes, int]  # (timestamp, frame bytes, link type)


class Readable(Protocol):
    def read(self, n: int = -1, /) -> bytes: ...


class CaptureFormatError(ValueError):
    pass


@dataclass
class CaptureInfo:
    """What the reader learned about the capture container (not the traffic)."""

    format: str = ""
    linktypes: list[int] = field(default_factory=list)
    truncated: bool = False
    skipped_blocks: int = 0

    def to_dict(self) -> dict[str, object]:
        return {
            "format": self.format,
            "linktypes": sorted(set(self.linktypes)),
            "truncated": self.truncated,
            "skipped_blocks": self.skipped_blocks,
        }


@dataclass
class _Interface:
    linktype: int
    ts_unit: float = 1e-6  # seconds per timestamp tick; pcapng default is microseconds
    ts_offset: int = 0


def read_exact(stream: Readable, n: int) -> bytes:
    """Read ``n`` bytes, tolerating short reads from pipes; fewer only at EOF."""
    buf = b""
    while len(buf) < n:
        chunk = stream.read(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def _check_record(n: int, what: str) -> None:
    if n > MAX_RECORD_BYTES:
        raise CaptureFormatError(f"{what} of {n} bytes exceeds the {MAX_RECORD_BYTES} byte limit")


# --------------------------------------------------------------------- pcap


def iter_pcap(stream: Readable, magic: bytes, info: CaptureInfo) -> Iterator[Frame]:
    """Yield frames from a classic pcap stream whose 4-byte magic was already consumed."""
    endian, divisor = PCAP_MAGICS[magic]
    info.format = "pcap"
    header = read_exact(stream, 20)
    if len(header) < 20:
        info.truncated = True
        return
    network = struct.unpack(endian + "HHiIII", header)[5]
    # The upper bits of the link-type field may carry FCS metadata (pcap spec §4).
    linktype = network & 0x0FFFFFFF
    info.linktypes.append(linktype)
    record = struct.Struct(endian + "IIII")
    while True:
        head = read_exact(stream, record.size)
        if not head:
            return
        if len(head) < record.size:
            info.truncated = True
            return
        sec, frac, caplen, _origlen = record.unpack(head)
        _check_record(caplen, "pcap record")
        buf = read_exact(stream, caplen)
        if len(buf) < caplen:
            info.truncated = True
            return
        yield sec + frac / divisor, buf, linktype


# ------------------------------------------------------------------- pcapng


def _ts_unit(raw: int) -> float:
    # MSB clear: 10^-value seconds; MSB set: 2^-(value & 0x7f) seconds.
    if raw & 0x80:
        return 2.0 ** -(raw & 0x7F)
    return 10.0**-raw


def _parse_idb(body: bytes, endian: str) -> _Interface:
    if len(body) < 8:
        raise CaptureFormatError("pcapng interface description block too short")
    linktype = struct.unpack(endian + "H", body[:2])[0]
    iface = _Interface(linktype=linktype)
    pos = 8
    while pos + 4 <= len(body):
        code, length = struct.unpack(endian + "HH", body[pos : pos + 4])
        value = body[pos + 4 : pos + 4 + length]
        if code == OPT_ENDOFOPT:
            break
        if code == OPT_IF_TSRESOL and length >= 1:
            iface.ts_unit = _ts_unit(value[0])
        elif code == OPT_IF_TSOFFSET and length >= 8:
            iface.ts_offset = struct.unpack(endian + "q", value[:8])[0]
        pos += 4 + length + (-length % 4)
    return iface


def _check_block(total: int, minimum: int) -> None:
    if total < minimum or total % 4:
        raise CaptureFormatError(f"invalid pcapng block length {total}")
    _check_record(total, "pcapng block")


def iter_pcapng(stream: Readable, info: CaptureInfo) -> Iterator[Frame]:
    """Yield frames from a pcapng stream whose first 4 bytes (SHB type) were consumed."""
    info.format = "pcapng"
    endian = "<"
    interfaces: list[_Interface] = []
    last_ts = 0.0
    head = PCAPNG_MAGIC + read_exact(stream, 4)

    while True:
        if len(head) < 8:
            info.truncated = bool(head)
            return
        if head[:4] == PCAPNG_MAGIC:
            # The SHB type is a byte palindrome; the byte order of its length
            # field is only known after the byte-order magic that follows.
            magic = read_exact(stream, 4)
            if len(magic) < 4:
                info.truncated = True
                return
            if struct.unpack("<I", magic)[0] == BYTE_ORDER_MAGIC:
                endian = "<"
            elif struct.unpack(">I", magic)[0] == BYTE_ORDER_MAGIC:
                endian = ">"
            else:
                raise CaptureFormatError("bad pcapng byte-order magic")
            total = struct.unpack(endian + "I", head[4:8])[0]
            _check_block(total, minimum=28)
            if len(read_exact(stream, total - 12)) < total - 12:
                info.truncated = True
                return
            interfaces = []  # interface ids are scoped to their section
            head = read_exact(stream, 8)
            continue

        btype, total = struct.unpack(endian + "II", head)
        _check_block(total, minimum=12)
        rest = read_exact(stream, total - 8)
        if len(rest) < total - 8:
            info.truncated = True
            return
        body = rest[:-4]

        if btype == IDB:
            iface = _parse_idb(body, endian)
            interfaces.append(iface)
            info.linktypes.append(iface.linktype)
        elif btype in (EPB, PB):
            if len(body) < 20:
                raise CaptureFormatError("pcapng packet block too short")
            if btype == EPB:
                if_id, ts_hi, ts_lo, caplen, _ = struct.unpack(endian + "IIIII", body[:20])
            else:
                if_id, _drops, ts_hi, ts_lo, caplen, _ = struct.unpack(endian + "HHIIII", body[:20])
            if if_id >= len(interfaces):
                raise CaptureFormatError(f"pcapng packet references undefined interface {if_id}")
            if caplen > len(body) - 20:
                raise CaptureFormatError("pcapng captured length exceeds its block")
            iface = interfaces[if_id]
            last_ts = ((ts_hi << 32) | ts_lo) * iface.ts_unit + iface.ts_offset
            yield last_ts, body[20 : 20 + caplen], iface.linktype
        elif btype == SPB:
            # Simple Packet Blocks carry no timestamp and always use interface 0.
            if not interfaces or len(body) < 4:
                raise CaptureFormatError("pcapng simple packet block without an interface")
            origlen = struct.unpack(endian + "I", body[:4])[0]
            yield last_ts, body[4 : 4 + min(origlen, len(body) - 4)], interfaces[0].linktype
        else:
            info.skipped_blocks += 1
        head = read_exact(stream, 8)
