"""A minimal, bounded DNS responder on Kali for the DNS experiments.

    sudo python3 kali_dns_responder.py [SECONDS]      # default 300, at most 900

The lab has no resolver and no internet, so the victim's lookups for
exp12-dns-nxdomain and exp13-dns-tunnel need something to answer them. This
listens on 10.77.0.10:53 (UDP), answers ONLY queries from 10.77.0.20 and
nothing else: names under lab-tunnel.test get an empty NOERROR answer (no
records), every other name gets NXDOMAIN. It never resolves anything, never
forwards, and stops after SECONDS or 2000 answers, whichever comes first.

Refuses unless it runs as root on 10.77.0.10 and port 53 is free there.
"""

from __future__ import annotations

import os
import socket
import struct
import sys
import time

LISTEN = "10.77.0.10"
VICTIM = "10.77.0.20"
TUNNEL_DOMAIN = b"lab-tunnel.test"
MAX_ANSWERS = 2000
MAX_SECONDS = 900


def _qname(packet: bytes) -> tuple[bytes, int] | None:
    labels, i = [], 12
    while i < len(packet):
        n = packet[i]
        if n == 0:
            return b".".join(labels).lower(), i + 5  # end of name + QTYPE + QCLASS
        if n & 0xC0 or i + 1 + n > len(packet):
            return None
        labels.append(packet[i + 1 : i + 1 + n])
        i += 1 + n
    return None


def answer(query: bytes) -> bytes | None:
    """The reply for one query, or None for anything that is not a plain query."""
    if len(query) < 17:
        return None
    ident, flags, qdcount = struct.unpack("!HHH", query[:6])
    if flags & 0x8000 or qdcount != 1:
        return None
    parsed = _qname(query)
    if parsed is None:
        return None
    name, end = parsed
    tunnel = name == TUNNEL_DOMAIN or name.endswith(b"." + TUNNEL_DOMAIN)
    rcode = 0 if tunnel else 3  # NOERROR (no records) or NXDOMAIN
    reply_flags = 0x8000 | (flags & 0x0100) | 0x0080 | rcode  # QR, copy RD, RA
    return struct.pack("!HHHHHH", ident, reply_flags, 1, 0, 0, 0) + query[12:end]


def main(argv: list[str]) -> int:
    seconds = int(argv[0]) if argv else 300
    if not 1 <= seconds <= MAX_SECONDS:
        print(f"SECONDS must be 1-{MAX_SECONDS}", file=sys.stderr)
        return 2
    if os.geteuid() != 0:
        print("run with sudo (port 53 needs root)", file=sys.stderr)
        return 1
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((LISTEN, 53))
    except OSError as exc:
        print(f"cannot listen on {LISTEN}:53 ({exc}); not the lab attacker or port busy", file=sys.stderr)
        return 1
    sock.settimeout(1.0)
    end, answered, ignored = time.monotonic() + seconds, 0, 0
    print(f"answering DNS from {VICTIM} on {LISTEN}:53 for {seconds}s")
    print("NXDOMAIN for every name, empty NOERROR for *.lab-tunnel.test", flush=True)
    with sock:
        while time.monotonic() < end and answered < MAX_ANSWERS:
            try:
                data, (peer, port) = sock.recvfrom(512)
            except TimeoutError:
                continue
            reply = answer(data) if peer == VICTIM else None
            if reply is None:
                ignored += 1
                continue
            sock.sendto(reply, (peer, port))
            answered += 1
    print(f"responder stopped: {answered} answers, {ignored} packets ignored")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
