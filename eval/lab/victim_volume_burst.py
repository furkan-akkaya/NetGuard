"""exp14-rate-volume (Ubuntu side): one bounded upload to Kali.

    python3 victim_volume_burst.py      # when kali_rate_burst.py says so

Sends 48 MB of zeros once to 10.77.0.10:9099 (the receiver started by
kali_rate_burst.py), so the victim's outgoing volume jumps far above its own
13-minute baseline (NG-VOL-001, source 10.77.0.20). Refuses unless it runs on
10.77.0.20; sends nothing anywhere else.

Paced at 4 MB/s (about 12 s). Unpaced, a virtual link moves 48 MB in well
under a second and tcpdump drops part of it (rehearsal: 1576 kernel drops,
11 MB captured), so the capture would not show what was sent. Paced, even an
upload split across two 60 s intervals puts at least 24 MB in one of them,
above the rule's 20 MB floor.
"""

from __future__ import annotations

import socket
import subprocess
import sys
import time

VICTIM, TARGET = "10.77.0.20", ("10.77.0.10", 9099)
TOTAL, CHUNK = 48 * 1024 * 1024, 64 * 1024
RATE = 4 * 1024 * 1024  # bytes per second


def main() -> int:
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
                ahead = sent / RATE - (time.monotonic() - started)
                if ahead > 0:
                    time.sleep(ahead)
    except OSError as exc:
        print(f"upload stopped after {sent} bytes: {exc}", file=sys.stderr)
        return 1
    print(f"sent {sent} bytes to {TARGET[0]}:{TARGET[1]} in {time.monotonic() - started:.1f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
