"""exp14-rate-volume (Ubuntu side): one bounded upload to Kali.

    python3 victim_volume_burst.py [--rate MIB_PER_S]     # when kali_rate_burst.py says so

Sends 48 MiB of zeros once to 10.77.0.10:9099 (the receiver started by
kali_rate_burst.py), so the victim's outgoing volume jumps far above its own
13-minute baseline (NG-VOL-001, source 10.77.0.20). Refuses unless it runs on
10.77.0.20; sends nothing anywhere else.

Paced, by default at 1 MiB/s (48 s; --rate 0.5-4). The capture has to keep
up: unpaced, a virtual link moved 48 MiB in under a second and tcpdump lost
1576 packets (namespace rehearsal); at 4 MiB/s the first real UTM run lost
9945 of 59091 packets with tcpdump's default buffer, so that run does not
count. At 1 MiB/s the upload spans at most two 60 s intervals, and one of
them still holds at least 24 MiB, above the rule's 20 MB floor.
"""

from __future__ import annotations

import socket
import subprocess
import sys
import time

VICTIM, TARGET = "10.77.0.20", ("10.77.0.10", 9099)
TOTAL, CHUNK = 48 * 1024 * 1024, 64 * 1024
MIB = 1024 * 1024
DEFAULT_RATE_MIB, MIN_RATE_MIB, MAX_RATE_MIB = 1.0, 0.5, 4.0


def parse_rate(argv: list[str]) -> float:
    """Upload rate in MiB/s from ``--rate X``; bounded so the upload stays a short, one-off burst."""
    if not argv:
        return DEFAULT_RATE_MIB
    if len(argv) != 2 or argv[0] != "--rate":
        raise ValueError("usage: victim_volume_burst.py [--rate MIB_PER_S]")
    rate = float(argv[1])
    if not MIN_RATE_MIB <= rate <= MAX_RATE_MIB:
        raise ValueError(f"--rate must be {MIN_RATE_MIB:g}-{MAX_RATE_MIB:g} MiB/s")
    return rate


def main(argv: list[str]) -> int:
    try:
        rate = parse_rate(argv) * MIB
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 2
    addrs = subprocess.run(["ip", "-o", "-4", "addr", "show"], capture_output=True, text=True, check=False).stdout  # noqa: S607
    if f" {VICTIM}/" not in addrs:
        print(f"this host does not have {VICTIM}: not the lab victim, refusing", file=sys.stderr)
        return 1
    sent, block = 0, bytes(CHUNK)
    started = time.monotonic()
    try:
        with socket.create_connection(TARGET, timeout=10) as s:
            while sent < TOTAL:
                s.sendall(block)
                sent += CHUNK
                ahead = sent / rate - (time.monotonic() - started)
                if ahead > 0:
                    time.sleep(ahead)
    except OSError as exc:
        print(f"upload stopped after {sent} bytes: {exc}", file=sys.stderr)
        return 1
    elapsed = time.monotonic() - started
    print(f"sent {sent} bytes to {TARGET[0]}:{TARGET[1]} in {elapsed:.1f}s (paced at {rate / MIB:g} MiB/s)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
