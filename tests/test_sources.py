import io

import dpkt
import pytest

from netguard.lab.scenarios import ATTACKER, SERVER
from netguard.lab.synth import write_pcap
from netguard.models import SYN
from netguard.sources import CaptureFormatError, iter_frames, open_capture


class NonSeekable(io.RawIOBase):
    """Behaves like a pipe: read() works, seek()/tell() do not."""

    def __init__(self, data: bytes) -> None:
        self._buf = io.BytesIO(data)

    def readable(self) -> bool:
        return True

    def readinto(self, b):
        chunk = self._buf.read(min(len(b), 7))  # deliberately tiny reads
        b[: len(chunk)] = chunk
        return len(chunk)


def _pcap_bytes(n: int = 3) -> bytes:
    out = io.BytesIO()
    writer = dpkt.pcap.Writer(out)
    for i in range(n):
        writer.writepkt(ATTACKER.tcp(SERVER, 40000, 20 + i, SYN), ts=100.0 + i)
    return out.getvalue()


def test_reads_pcap_file(tmp_path):
    path = tmp_path / "x.pcap"
    write_pcap(path, [(1.0, ATTACKER.tcp(SERVER, 1, 2, SYN))])
    with open_capture(path) as frames:
        got = list(frames)
    assert len(got) == 1
    assert got[0][0] == pytest.approx(1.0)
    assert got[0][2] == 1  # Ethernet


def test_reads_pcap_from_non_seekable_stream():
    frames = list(iter_frames(io.BufferedReader(NonSeekable(_pcap_bytes(5)))))
    assert [round(ts) for ts, _, _ in frames] == [100, 101, 102, 103, 104]


def test_reads_pcapng():
    out = io.BytesIO()
    writer = dpkt.pcapng.Writer(out)
    writer.writepkt(ATTACKER.tcp(SERVER, 1, 2, SYN), ts=5.0)
    out.seek(0)
    frames = list(iter_frames(out))
    assert len(frames) == 1
    assert frames[0][0] == pytest.approx(5.0)


def test_empty_input_yields_nothing():
    assert list(iter_frames(io.BytesIO(b""))) == []


def test_rejects_non_capture_files():
    with pytest.raises(CaptureFormatError, match="not a pcap"):
        list(iter_frames(io.BytesIO(b"GET / HTTP/1.1\r\n")))
