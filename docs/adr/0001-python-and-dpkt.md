# ADR-0001: Python 3.11+ with dpkt as the only runtime dependency

- **Status:** Accepted
- **Date:** 2026-10-20

## Context

NetGuard must run on an M1 MacBook, a Kali VM under UTM, and a 4 GB Ubuntu
server. It has to be readable by its author while he is learning the domain,
and it has to be easy to test. Packet parsing speed matters, but this MVP does
not target line-rate capture.

## Options considered

| Option | Pros | Cons |
|---|---|---|
| **Python + dpkt** | Fast pure-Python parsing (thin `struct` wrappers), tiny, stable API, reads pcap and pcapng from streams | Fewer protocols than Scapy, cannot capture on its own |
| Python + Scapy | Huge protocol coverage, great for crafting packets | Roughly 10× slower to dissect (it builds rich layered objects), heavy import, a large dependency for a parser |
| Python + PyShark | Full Wireshark dissectors | Spawns `tshark`, very slow, needs Wireshark installed |
| Go + gopacket | 10–50× faster, single static binary | Slower learning loop for the author, less common in detection-engineering teaching material |
| Rust + etherparse/pcap | Fastest, memory-safe | Highest learning cost, slow iteration for an MVP |
| Build on Zeek/Suricata | Production-grade parsing | The project becomes "Zeek scripts" rather than a tool the author built and understands |

## Decision

Use Python ≥ 3.11 (it brings `tomllib` and faster CPython) with **dpkt** for
decoding. Use the standard library for everything else: `argparse`, `tomllib`
and `json`.

## Consequences

- Measured throughput is ~60k packets/s on one M1 core. That is enough for
  home and lab networks and for offline analysis. Saturated gigabit links are
  out of reach.
- The `decode()` → `Packet` boundary isolates dpkt. If a hot path needs it
  later, the decoder can be swapped (for Scapy, a Rust extension, or Zeek logs)
  without touching any detector.
- Packet *crafting* for tests also uses dpkt (`lab/synth.py`), so Scapy is not
  needed in development either.
