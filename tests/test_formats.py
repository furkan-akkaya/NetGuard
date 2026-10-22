import io
import struct

import pytest

from netguard.decode import DLT_EN10MB, DLT_NULL
from netguard.engine import analyze_frames
from netguard.formats import MAX_RECORD_BYTES, CaptureFormatError, CaptureInfo
from netguard.lab.scenarios import ATTACKER, SERVER
from netguard.lab.synth import write_pcap
from netguard.models import SYN
from netguard.sources import iter_frames

FRAME = ATTACKER.tcp(SERVER, 40000, 22, SYN)
# BSD loopback (DLT_NULL): 4-byte host-order address family, then the IP packet.
LOOPBACK_FRAME = struct.pack("<I", 2) + FRAME[14:]


def _pad(b: bytes) -> bytes:
    return b + b"\x00" * (-len(b) % 4)


def _block(btype: int, body: bytes, e: str = "<") -> bytes:
    body = _pad(body)
    total = 12 + len(body)
    return struct.pack(e + "II", btype, total) + body + struct.pack(e + "I", total)


def shb(e: str = "<") -> bytes:
    return _block(0x0A0D0D0A, struct.pack(e + "IHHq", 0x1A2B3C4D, 1, 0, -1), e)


def idb(linktype: int, tsresol: int | None = None, e: str = "<") -> bytes:
    body = struct.pack(e + "HHI", linktype, 0, 65535)
    if tsresol is not None:
        body += struct.pack(e + "HH", 9, 1) + _pad(bytes([tsresol]))
        body += struct.pack(e + "HH", 0, 0)
    return _block(1, body, e)


def epb(if_id: int, ticks: int, data: bytes, e: str = "<") -> bytes:
    head = struct.pack(e + "IIIII", if_id, ticks >> 32, ticks & 0xFFFFFFFF, len(data), len(data))
    return _block(6, head + data, e)


def _frames(data: bytes, info: CaptureInfo | None = None):
    return list(iter_frames(io.BytesIO(data), "test", info))


def test_pcapng_multi_interface_keeps_each_link_type():
    data = shb() + idb(DLT_EN10MB) + idb(DLT_NULL) + epb(0, 1_000_000, FRAME) + epb(1, 2_000_000, LOOPBACK_FRAME)
    info = CaptureInfo()
    frames = _frames(data, info)
    assert [(ts, lt) for ts, _, lt in frames] == [(1.0, DLT_EN10MB), (2.0, DLT_NULL)]
    assert info.format == "pcapng"
    assert info.linktypes == [DLT_EN10MB, DLT_NULL]
    # Both frames decode to the same TCP SYN: the loopback one is not Ethernet garbage.
    result = analyze_frames(frames)
    assert result.stats.protocols == {"tcp": 2}
    assert result.stats.decode_errors == 0


def test_pcapng_nanosecond_resolution_and_big_endian():
    data = shb(">") + idb(DLT_EN10MB, tsresol=9, e=">") + epb(0, 1_500_000_000, FRAME, e=">")
    assert _frames(data)[0][0] == pytest.approx(1.5)


def test_pcapng_power_of_two_resolution():
    data = shb() + idb(DLT_EN10MB, tsresol=0x80 | 10) + epb(0, 3 * 1024, FRAME)
    assert _frames(data)[0][0] == pytest.approx(3.0)


def test_pcapng_unknown_blocks_are_skipped_and_counted():
    info = CaptureInfo()
    data = shb() + idb(DLT_EN10MB) + _block(0x00000005, b"stats") + epb(0, 0, FRAME)
    assert len(_frames(data, info)) == 1
    assert info.skipped_blocks == 1


def test_pcapng_simple_packet_block():
    spb = _block(3, struct.pack("<I", len(FRAME)) + FRAME)
    frames = _frames(shb() + idb(DLT_EN10MB) + epb(0, 7_000_000, FRAME) + spb)
    assert [ts for ts, _, _ in frames] == [7.0, 7.0]  # SPB has no timestamp: reuse the last one


def test_pcapng_new_section_resets_interfaces():
    data = shb() + idb(DLT_EN10MB) + epb(0, 0, FRAME) + shb() + epb(0, 0, FRAME)
    with pytest.raises(CaptureFormatError, match="undefined interface 0"):
        _frames(data)


def test_pcapng_truncated_tail_is_reported_not_raised():
    data = shb() + idb(DLT_EN10MB) + epb(0, 0, FRAME) + epb(0, 1, FRAME)
    info = CaptureInfo()
    frames = _frames(data[:-10], info)
    assert len(frames) == 1
    assert info.truncated


@pytest.mark.parametrize("total", [8, 13, MAX_RECORD_BYTES + 4])
def test_pcapng_rejects_bad_block_lengths(total):
    bad = struct.pack("<II", 6, total) + b"\x00" * 16
    with pytest.raises(CaptureFormatError, match="block"):
        _frames(shb() + idb(DLT_EN10MB) + bad)


def test_pcapng_caplen_larger_than_block_is_rejected():
    body = struct.pack("<IIIII", 0, 0, 0, 5000, 5000) + FRAME
    with pytest.raises(CaptureFormatError, match="exceeds"):
        _frames(shb() + idb(DLT_EN10MB) + _block(6, body))


def _pcap(records: bytes, magic: bytes = b"\xd4\xc3\xb2\xa1") -> bytes:
    return magic + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, DLT_EN10MB) + records


def test_pcap_hostile_caplen_is_rejected_before_reading():
    """Regression: dpkt read up to caplen (4 GiB) bytes of the input into one frame."""
    record = struct.pack("<IIII", 0, 0, 0xFFFFFFFF, 60)
    with pytest.raises(CaptureFormatError, match="exceeds"):
        _frames(_pcap(record))


def test_pcap_truncated_record_is_reported(tmp_path):
    path = tmp_path / "x.pcap"
    write_pcap(path, [(1.0, FRAME), (2.0, FRAME)])
    info = CaptureInfo()
    frames = _frames(path.read_bytes()[:-5], info)
    assert len(frames) == 1
    assert info.truncated
    assert info.format == "pcap"


def test_pcap_nanosecond_magic():
    record = struct.pack("<IIII", 3, 250_000_000, len(FRAME), len(FRAME)) + FRAME
    assert _frames(_pcap(record, b"\x4d\x3c\xb2\xa1"))[0][0] == pytest.approx(3.25)


def test_pcap_linktype_fcs_bits_are_masked():
    header = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 0x10000000 | DLT_EN10MB)
    record = struct.pack("<IIII", 0, 0, len(FRAME), len(FRAME)) + FRAME
    assert _frames(header + record)[0][2] == DLT_EN10MB


def test_unsupported_linktype_frames_are_counted_not_fatal():
    data = shb() + idb(DLT_EN10MB) + idb(147) + epb(0, 0, FRAME) + epb(1, 0, b"\x01\x02\x03")
    result = analyze_frames(_frames(data))
    assert result.stats.protocols == {"tcp": 1}
    assert result.stats.unsupported_linktypes == {147: 1}
