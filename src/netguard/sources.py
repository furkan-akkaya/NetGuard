"""Packet sources: pcap / pcapng files and byte streams (e.g. ``tcpdump -w -``).

Live capture is deliberately delegated to ``tcpdump``/``dumpcap``: they are
privileged, battle-tested and drop privileges after opening the interface, so
NetGuard itself never needs to run as root::

    sudo tcpdump -i eth0 -U -w - | netguard analyze -

Only sequential ``read()`` is used, so non-seekable streams (pipes, stdin) work
exactly like files.
"""

from __future__ import annotations

import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from netguard.formats import (
    PCAP_MAGICS,
    PCAPNG_MAGIC,
    CaptureFormatError,
    CaptureInfo,
    Frame,
    Readable,
    iter_pcap,
    iter_pcapng,
    read_exact,
)

__all__ = ["CaptureFormatError", "CaptureInfo", "iter_frames", "open_capture"]


def iter_frames(stream: Readable, name: str = "<stream>", info: CaptureInfo | None = None) -> Iterator[Frame]:
    """Yield ``(timestamp, frame_bytes, linktype)`` from a pcap or pcapng stream.

    Pass a :class:`CaptureInfo` to learn the container format, the link types
    seen and whether the capture ended in a truncated record.
    """
    info = info if info is not None else CaptureInfo()
    magic = read_exact(stream, 4)
    if not magic:
        return  # empty input: nothing to analyze
    try:
        if magic in PCAP_MAGICS:
            yield from iter_pcap(stream, magic, info)
        elif magic == PCAPNG_MAGIC:
            yield from iter_pcapng(stream, info)
        else:
            raise CaptureFormatError(f"not a pcap/pcapng file (magic {magic.hex()})")
    except CaptureFormatError as exc:
        raise CaptureFormatError(f"{name}: {exc}") from None


@contextmanager
def open_capture(path: str | Path, info: CaptureInfo | None = None) -> Iterator[Iterator[Frame]]:
    """Open a capture file, or stdin when ``path`` is ``"-"``."""
    if str(path) == "-":
        yield iter_frames(sys.stdin.buffer, "<stdin>", info)
        return
    with open(path, "rb") as fh:
        yield iter_frames(fh, str(path), info)
