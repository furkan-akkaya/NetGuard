"""Lookups from the victim for the DNS experiments (exp12, exp13).

    python3 victim_dns_queries.py nxdomain      # exp12-dns-nxdomain: 40 random names, ~20 s
    python3 victim_dns_queries.py tunnel        # exp13-dns-tunnel: 80 long labels, ~40 s

Run on the Ubuntu victim, as a normal user, in a SECOND terminal while
victim-capture.sh captures and kali_dns_responder.py answers on Kali. Every
query goes to 10.77.0.10:53 only, at a fixed pace; nothing is resolved. The
names are generated here (random DGA-like <label>.test, or <label>.t.lab-tunnel.test)
and carry no data. Writes ~/ng-captures/NAME.attack.txt for eval/lab/ingest.py.
"""

from __future__ import annotations

import secrets
import socket
import struct
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

VICTIM = "10.77.0.20"
RESOLVER = ("10.77.0.10", 53)
MODES = {
    # name, queries, pause (s), label alphabet, label length, domain
    "nxdomain": ("exp12-dns-nxdomain", 40, 0.5, "abcdefghijklmnopqrstuvwxyz0123456789", 12, "test"),
    "tunnel": ("exp13-dns-tunnel", 80, 0.5, "abcdefghijklmnopqrstuvwxyz234567", 32, "t.lab-tunnel.test"),
}


def _query(ident: int, name: str) -> bytes:
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    return struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)


def main(argv: list[str]) -> int:
    if len(argv) != 1 or argv[0] not in MODES:
        print(__doc__, file=sys.stderr)
        return 2
    name, count, pause, alphabet, length, domain = MODES[argv[0]]
    addrs = subprocess.run(["ip", "-o", "-4", "addr", "show"], capture_output=True, text=True, check=False).stdout  # noqa: S607
    if f" {VICTIM}/" not in addrs:
        print(f"this host does not have {VICTIM}: not the lab victim, refusing", file=sys.stderr)
        return 1
    answered = {0: 0, 3: 0}
    start = datetime.now(UTC).isoformat()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(1.0)
        for i in range(count):
            label = "".join(secrets.choice(alphabet) for _ in range(length))
            sock.sendto(_query(i + 1, f"{label}.{domain}"), RESOLVER)
            try:
                reply = sock.recv(512)
                rcode = reply[3] & 0x0F
                answered[rcode] = answered.get(rcode, 0) + 1
            except TimeoutError:
                pass
            time.sleep(pause)
    replies = sum(answered.values())
    out = Path.home() / "ng-captures"
    out.mkdir(exist_ok=True)
    record = out / f"{name}.attack.txt"
    record.write_text(
        f"name: {name}\ntool: python3 DNS client ({Path(__file__).name})\n"
        f"tool_version: Python {sys.version.split()[0]}\n"
        f"command: {count} A queries for random {length}-character labels under {domain} to "
        f"{RESOLVER[0]}:53, one every {pause}s\n"
        f"start_utc: {start}\nend_utc: {datetime.now(UTC).isoformat()}\n"
        f"replies: {replies} (NOERROR {answered.get(0, 0)}, NXDOMAIN {answered.get(3, 0)})\n",
        encoding="utf-8",
    )
    print(record.read_text(encoding="utf-8"))
    if replies == 0:
        print("no replies: is kali_dns_responder.py running? The capture is still a result; say so.", file=sys.stderr)
    print("Done. Wait ~15 s, then press Ctrl-C in the capture terminal.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
