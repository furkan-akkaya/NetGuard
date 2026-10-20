"""Packet sources: pcap / pcapng files and byte streams (e.g. ``tcpdump -w -``).

Live capture is deliberately delegated to ``tcpdump``/``dumpcap``: they are
privileged, battle-tested and drop privileges after opening the interface, so
NetGuard itself never needs to run as root::

    sudo tcpdump -i eth0 -U -w - | netguard analyze -
"""

from __future__ import annotations

import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO

import dpkt

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1",  # little-endian, microseconds
    b"\xa1\xb2\xc3\xd4",  # big-endian, microseconds
    b"\x4d\x3c\xb2\xa1",  # little-endian, nanoseconds
    b"\xa1\xb2\x3c\x4d",  # big-endian, nanoseconds
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"


class CaptureFormatError(ValueError):
    pass


class _Prepended:
    """A minimal read-only stream that replays already-consumed bytes first.

    Needed because we must sniff the magic number of a non-seekable stream
    (stdin) before choosing the right reader.
    """

    def __init__(self, head: bytes, rest: BinaryIO, name: str) -> None:
        self._head = head
        self._rest = rest
        self.name = name

    def read(self, n: int = -1) -> bytes:
        if not self._head:
            return self._rest.read(n)
        if n < 0:
            data, self._head = self._head + self._rest.read(), b""
            return data
        data, self._head = self._head[:n], self._head[n:]
        if len(data) < n:
            data += self._rest.read(n - len(data))
        return data


def _read_exact(stream: BinaryIO, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = stream.read(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def iter_frames(stream: BinaryIO, name: str = "<stream>") -> Iterator[tuple[float, bytes, int]]:
    """Yield ``(timestamp, frame_bytes, linktype)`` from a pcap or pcapng stream."""
    magic = _read_exact(stream, 4)
    if not magic:
        return  # empty input: nothing to analyze
    wrapped = _Prepended(magic, stream, name)

    if magic in PCAP_MAGICS:
        reader = dpkt.pcap.Reader(wrapped)
        linktype = reader.datalink()
        for ts, buf in reader:
            yield float(ts), bytes(buf), linktype
    elif magic == PCAPNG_MAGIC:
        ng = dpkt.pcapng.Reader(wrapped)
        # dpkt exposes the link type of the first interface; multi-interface
        # pcapng files with mixed link types are rare and not supported yet.
        linktype = ng.datalink()
        for ts, buf in ng:
            yield float(ts), bytes(buf), linktype
    else:
        raise CaptureFormatError(f"{name}: not a pcap/pcapng file (magic {magic.hex()})")


@contextmanager
def open_capture(path: str | Path) -> Iterator[Iterator[tuple[float, bytes, int]]]:
    """Open a capture file, or stdin when ``path`` is ``"-"``."""
    if str(path) == "-":
        yield iter_frames(sys.stdin.buffer, "<stdin>")
        return
    with open(path, "rb") as fh:
        yield iter_frames(fh, str(path))
