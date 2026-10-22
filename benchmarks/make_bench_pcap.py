"""Write the reference benchmark capture used in docs/EVALUATION.md § Performance.

20 000 benign TCP connections (handshake, 3 request/response pairs, FIN close)
between 50 clients and 10 servers, plus one 1000-port SYN scan: 242 003 frames.
Deterministic, so every run and every machine benchmarks the same bytes.

    uv run python benchmarks/make_bench_pcap.py /tmp/bench.pcap
    /usr/bin/time -l uv run netguard analyze -f json /tmp/bench.pcap > /dev/null   # macOS
    /usr/bin/time -v uv run netguard analyze -f json /tmp/bench.pcap > /dev/null   # Linux
"""

from __future__ import annotations

import sys

from netguard.lab.scenarios import ATTACKER, SERVER, T0
from netguard.lab.synth import Frame, Host, syn_probe, tcp_handshake, write_pcap

CONNECTIONS = 20_000


def build() -> list[Frame]:
    clients = [Host(f"10.1.0.{i + 1}", f"02:00:00:01:00:{i + 1:02x}") for i in range(50)]
    servers = [Host(f"10.2.0.{i + 1}", f"02:00:00:02:00:{i + 1:02x}") for i in range(10)]
    frames: list[Frame] = []
    for n in range(CONNECTIONS):
        client, server = clients[n % len(clients)], servers[n % len(servers)]
        frames += tcp_handshake(client, server, T0 + n * 0.01, 20_000 + n % 40_000, 443)
    for i, port in enumerate(range(1, 1001)):
        frames += syn_probe(ATTACKER, SERVER, T0 + 50 + i * 0.001, port, open_=port in (22, 80, 443))
    return frames


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "bench.pcap"
    print(f"wrote {path} ({write_pcap(path, build())} frames)")
