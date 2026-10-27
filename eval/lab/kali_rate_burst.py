"""exp14-rate-volume (Kali side): a learned baseline, then a bounded change.

    python3 kali_rate_burst.py          # on Kali, after the victim capture is running

NG-RATE-001 and NG-VOL-001 compare each host with its OWN history: they need
ten 60 s intervals of baseline before they judge anything. This runs

1. 13 minutes of paced benign client traffic to the victim (an SSH banner
   read and a ping every 4-9 s, like kali-benign.sh),
2. a connection burst: 300 TCP connections to 10.77.0.20:22 at 10 per second
   (30 s), each reading the SSH banner and closing (NG-RATE-001, source
   10.77.0.10), and
3. a receiver on 10.77.0.10:9099 for the victim's one bounded upload
   (victim_volume_burst.py, 48 MB; NG-VOL-001, source 10.77.0.20). It accepts
   only 10.77.0.20, discards the data and stops after 180 s or 64 MB.

Refuses unless it runs on 10.77.0.10 and the victim's SSH port answers.
Writes ~/ng-experiments/exp14-rate-volume.attack.txt for eval/lab/ingest.py.
"""

from __future__ import annotations

import random
import socket
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

NAME = "exp14-rate-volume"
ATTACKER, VICTIM, SSH, RECV_PORT = "10.77.0.10", "10.77.0.20", 22, 9099
BASELINE_SECONDS = 780
BURST_CONNECTIONS, BURST_RATE = 300, 10.0
MAX_UPLOAD, RECV_SECONDS = 64 * 1024 * 1024, 180


def _banner() -> bool:
    try:
        with socket.create_connection((VICTIM, SSH), timeout=3) as s:
            s.settimeout(3)
            s.recv(64)
        return True
    except OSError:
        return False


def _listen() -> socket.socket:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((ATTACKER, RECV_PORT))
    srv.listen(1)
    srv.settimeout(RECV_SECONDS)
    return srv


def _receive(srv: socket.socket) -> int:
    total = 0
    with srv:
        try:
            conn, (peer, _) = srv.accept()
        except TimeoutError:
            return 0
        with conn:
            if peer != VICTIM:
                return 0
            conn.settimeout(30)
            while total < MAX_UPLOAD:
                try:
                    chunk = conn.recv(65536)
                except TimeoutError:
                    break
                if not chunk:
                    break
                total += len(chunk)
    return total


def main() -> int:
    addrs = subprocess.run(["ip", "-o", "-4", "addr", "show"], capture_output=True, text=True, check=False).stdout  # noqa: S607
    if f" {ATTACKER}/" not in addrs:
        print(f"this host does not have {ATTACKER}: not the lab attacker, refusing", file=sys.stderr)
        return 1
    if not _banner():
        print(f"{VICTIM}:{SSH} does not answer: refusing (nothing else was sent)", file=sys.stderr)
        return 1
    answer = input(f"Is 'victim-capture.sh {NAME}' running on Ubuntu (ready line shown)? Type 'capture-running': ")
    if answer.strip() != "capture-running":
        print("not confirmed; nothing was sent", file=sys.stderr)
        return 1

    start = datetime.now(UTC).isoformat()
    end = time.monotonic() + BASELINE_SECONDS
    cycles = 0
    print(f"phase 1: {BASELINE_SECONDS}s of paced benign traffic ...")
    while time.monotonic() < end:
        subprocess.run(["ping", "-c", "1", "-W", "2", VICTIM], capture_output=True, check=False)  # noqa: S603, S607
        _banner()
        cycles += 1
        time.sleep(random.uniform(4, 9))  # noqa: S311 - pacing, not security
    print(f"phase 2: {BURST_CONNECTIONS} connections at {BURST_RATE:g}/s ...")
    burst_start = datetime.now(UTC).isoformat()
    ok = 0
    for _ in range(BURST_CONNECTIONS):
        ok += _banner()
        time.sleep(1 / BURST_RATE)
    srv = _listen()  # listening BEFORE the prompt, so an immediate upload is not refused
    print(f"phase 3: waiting up to {RECV_SECONDS}s for the upload.")
    print(">>> NOW on Ubuntu, in a second terminal: python3 victim_volume_burst.py", flush=True)
    received = _receive(srv)
    out = Path.home() / "ng-experiments"
    out.mkdir(exist_ok=True)
    record = out / f"{NAME}.attack.txt"
    record.write_text(
        f"name: {NAME}\ntool: python3 ({Path(__file__).name})\ntool_version: Python {sys.version.split()[0]}\n"
        f"command: {BASELINE_SECONDS}s benign baseline ({cycles} cycles), then {BURST_CONNECTIONS} TCP connects "
        f"to {VICTIM}:{SSH} at {BURST_RATE:g}/s ({ok} answered), then one upload from {VICTIM} to "
        f"{ATTACKER}:{RECV_PORT} ({received} bytes received)\n"
        f"start_utc: {start}\nburst_start_utc: {burst_start}\nend_utc: {datetime.now(UTC).isoformat()}\n",
        encoding="utf-8",
    )
    print(record.read_text(encoding="utf-8"))
    print("Done. Wait ~15 s, then press Ctrl-C in the Ubuntu capture.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
