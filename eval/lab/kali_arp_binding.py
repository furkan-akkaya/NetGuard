"""exp11-arp-binding: a bounded ARP binding change for an UNUSED lab address.

    sudo python3 kali_arp_binding.py            # on Kali, after the victim capture is running

NG-ARP-001 alerts when an IP that was bound to one MAC is claimed by another.
The two-VM lab has no third host to impersonate, and impersonating a real host
(the victim or the Mac's UTM interface) would disrupt it. So this announces an
address nobody uses, 10.77.0.99, first from MAC 02:00:00:00:99:01 and then from
MAC 02:00:00:00:99:02 (locally administered, not real NICs): three gratuitous
ARP replies each, five seconds apart. No host's traffic is redirected. It tests
the binding-change logic on real frames, not a man-in-the-middle.

Refuses unless it runs as root on 10.77.0.10, 10.77.0.99 does not answer and is
not in the neighbour table, and you confirm the capture is running. Writes
~/ng-experiments/exp11-arp-binding.attack.txt for eval/lab/ingest.py.
"""

from __future__ import annotations

import os
import pwd
import socket
import struct
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

NAME = "exp11-arp-binding"
ATTACKER = "10.77.0.10"
UNUSED = "10.77.0.99"
MACS = ("02:00:00:00:99:01", "02:00:00:00:99:02")
FRAMES_PER_MAC = 3
PAUSE_SECONDS = 5.0


def _run(*cmd: str) -> str:
    return subprocess.run(cmd, capture_output=True, text=True, check=False).stdout  # noqa: S603


def _iface_with(ip: str) -> str | None:
    for line in _run("ip", "-o", "-4", "addr", "show").splitlines():
        parts = line.split()
        if len(parts) > 3 and parts[3].split("/")[0] == ip:
            return parts[1]
    return None


def _frame(mac: str) -> bytes:
    src = bytes.fromhex(mac.replace(":", ""))
    ip = socket.inet_aton(UNUSED)
    eth = b"\xff" * 6 + src + struct.pack("!H", 0x0806)
    # Gratuitous ARP reply: sender and target IP are both the announced address.
    arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2) + src + ip + b"\xff" * 6 + ip
    return eth + arp


def _invoking_user() -> pwd.struct_passwd | None:
    """The account that ran `sudo`: under sudo HOME is usually /root, but the
    record belongs in the lab user's ~/ng-experiments like the other runners'."""
    name = os.environ.get("SUDO_USER", "")
    if not name or name == "root":
        return None
    try:
        return pwd.getpwnam(name)
    except KeyError:
        return None


def main() -> int:
    if os.geteuid() != 0:
        print("run with sudo (raw frames need root); nothing was sent", file=sys.stderr)
        return 1
    iface = _iface_with(ATTACKER)
    if iface is None:
        print(f"this host does not have {ATTACKER}: not the lab attacker, refusing", file=sys.stderr)
        return 1
    if subprocess.run(["ping", "-c", "1", "-W", "1", UNUSED], capture_output=True, check=False).returncode == 0:  # noqa: S603, S607
        print(f"{UNUSED} answers ping: it is in use, refusing", file=sys.stderr)
        return 1
    neigh = _run("ip", "neigh", "show", UNUSED)
    if "lladdr" in neigh:
        print(f"{UNUSED} is in the neighbour table ({neigh.strip()}): it may be in use, refusing", file=sys.stderr)
        return 1
    answer = input(f"Is 'victim-capture.sh {NAME}' running on Ubuntu (ready line shown)? Type 'capture-running': ")
    if answer.strip() != "capture-running":
        print("not confirmed; nothing was sent", file=sys.stderr)
        return 1

    owner = _invoking_user()
    out = (Path(owner.pw_dir) if owner else Path.home()) / "ng-experiments"
    out.mkdir(exist_ok=True)
    start = datetime.now(UTC).isoformat()
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as sock:
        sock.bind((iface, 0))
        for i, mac in enumerate(MACS):
            if i:
                time.sleep(PAUSE_SECONDS)
            for _ in range(FRAMES_PER_MAC):
                sock.send(_frame(mac))
                time.sleep(0.5)
    command = f"gratuitous ARP for {UNUSED}: {FRAMES_PER_MAC}x from {MACS[0]}, then {FRAMES_PER_MAC}x from {MACS[1]}"
    record = out / f"{NAME}.attack.txt"
    record.write_text(
        f"name: {NAME}\ntool: python3 raw ARP ({Path(__file__).name})\n"
        f"tool_version: Python {sys.version.split()[0]}\ncommand: {command}\n"
        f"start_utc: {start}\nend_utc: {datetime.now(UTC).isoformat()}\ninterface: {iface}\n",
        encoding="utf-8",
    )
    if owner:  # the record belongs to the lab user, not root
        os.chown(out, owner.pw_uid, owner.pw_gid)
        os.chown(record, owner.pw_uid, owner.pw_gid)
    print(record.read_text(encoding="utf-8"))
    print("Done. Wait ~15 s, then press Ctrl-C in the Ubuntu capture. Transfer this record with the capture.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
