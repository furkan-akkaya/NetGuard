# Evaluation

This document reports **measured** behaviour only. Every number below can be
reproduced with the command next to it. If a result is synthetic, it says so.

## 1. Method

### Labelled scenarios

`src/netguard/lab/scenarios.py` defines small, deterministic traffic scenarios.
Each one is either **attack** or **benign**, and each lists the alerts it
*should* produce as `(detector, entity)` pairs:

| Detector | Entity |
|---|---|
| `portscan` | `scanner->target` |
| `hostsweep` | `scanner` |
| `arpspoof` | hijacked IP |

Scenarios are written to real pcap files and analysed through the full
pipeline: reader → decoder → engine → detectors.

Scoring is **per entity**:

- **TP:** an expected entity that produced ≥ 1 alert
- **FP:** an alerted entity that was not expected
- **FN:** an expected entity with no alert

Scoring per entity rather than per alert keeps a single noisy scenario from
dominating the totals. Raw alert counts are shown separately so that alert
*volume* stays visible.

Benign scenarios are deliberately **look-alikes**: traffic that a naive
detector would flag. Some scenarios exist specifically to expose known
weaknesses.

### Reproduce

```bash
uv run netguard lab evaluate
```

`tests/test_scenarios.py` pins the expected TP/FP/FN of every scenario. Any
change in detection quality fails CI until this document is updated.

## 2. Results: synthetic scenarios (v0.1.0)

| Scenario | Type | Packets | Alerts | TP | FP | FN | Outcome | Note |
|---|---|---:|---:|---:|---:|---:|---|---|
| `benign_office` | benign | 142 | 0 | 0 | 0 | 0 | quiet (correct) | 40 public HTTPS servers + internal SMB/RDP/HTTP |
| `monitoring_poller` | benign | 180 | 3 | 0 | 1 | 0 | false positive | Indistinguishable from a ping sweep by rate alone |
| `monitoring_poller_allowlisted` | benign | 180 | 0 | 0 | 0 | 0 | quiet (correct) | Same traffic, monitoring host allowlisted |
| `dhcp_reassignment` | benign | 2 | 1 | 0 | 1 | 0 | false positive | A single binding change cannot be told apart from spoofing |
| `passive_ftp` | benign | 266 | 1 | 0 | 1 | 0 | false positive | SYN counting ignores that every connection succeeded |
| `syn_scan_1000` | attack | 2003 | 1 | 1 | 0 | 0 | detected | Open ports 22/80/443 correctly reported |
| `xmas_scan` | attack | 398 | 1 | 1 | 0 | 0 | detected | Flagged as stealth scan |
| `slow_scan` | attack | 201 | 0 | 0 | 0 | 1 | **missed** | At most 5 probes in any 60 s window (threshold 15) |
| `ping_sweep` | attack | 259 | 1 | 1 | 0 | 0 | detected | Alive hosts reported |
| `arp_sweep` | attack | 259 | 1 | 1 | 0 | 0 | detected | |
| `arp_spoof_mitm` | attack | 70 | 4 | 2 | 0 | 0 | detected | 2 IPs × (MEDIUM, then HIGH escalation) |

**Totals:** TP = 6, FP = 3, FN = 1. Precision 0.67, recall 0.86 (entity level).

### How to read this

- These numbers measure **the logic against scenarios we designed**. They are
  not accuracy on real networks. Real traffic is messier: retransmissions,
  NAT, scanners with jitter and decoys, chatty IoT devices.
- The three false positives are **known and explained**. Each one has a
  mitigation on the [roadmap](../ROADMAP.md) (allowlist today; TRW in
  Phase 4, DHCP correlation in Phase 9).
- The missed slow scan shows the basic trade-off of window-based detection.
  A 60 s window keeps memory low and alerts fast, but an attacker who knows
  the window can stay under it.

## 3. Performance

| Workload | Packets | Wall time | Max RSS | Throughput |
|---|---:|---:|---:|---:|
| 20k benign TCP connections + one 1000-port scan | 242,003 | 3.7–5.6 s (3 runs) | 35–38 MB | ~45–65k pkt/s |

- Hardware: Apple M1, 16 GB. Python 3.11, single process.
- Command: `/usr/bin/time -l netguard analyze -f json bench.pcap`
- Wall time includes interpreter start-up. The variance comes from a busy
  laptop, not from the input.

For scale: a fully loaded 1 Gbit/s link carries roughly 80k–1.4M packets/s
depending on packet size, so NetGuard v0.1 is **not** a line-rate sensor. It
fits home and lab networks, low-traffic servers, and offline forensic analysis.

## 4. Robustness

- **Malformed input:** `tests/test_decode.py::test_decoder_survives_random_mutation`
  feeds 5,000 randomly mutated and truncated frames through the decoder. It
  must never raise.
- **Memory bounds:** per-key event caps, a key-count cap with garbage
  collection, flow-table and ARP-table caps. When a cap is hit, NetGuard
  degrades to *missed detections* (fail-open) and counts them. It never
  crashes and never grows without bound.

## 5. Known limitations (v0.1.0)

| Limitation | Impact | Planned fix |
|---|---|---|
| Fixed 60 s window | Slow scans evade detection | Long-horizon detector (4.4) |
| Outcome-blind counting | Bursts of successful connections (passive FTP, some P2P) look like scans | TRW (4.1) |
| No UDP scan detection | `nmap -sU` is invisible | UDP scan detector (4.3) |
| ARP: one change = alert | DHCP re-assignment and VRRP failover raise MEDIUM alerts | DHCP/lease correlation, flip-flop-only mode (Phase 9) |
| Spoofed source IPs | Decoy scans (`nmap -D`) split one scan into many sources | Target-centric correlation (Phase 9) |
| Idle-timeout reporting | Live alerts arrive ≥ 10 s after the scan pauses | Early-warning alerts (8.1) |
| No IP fragment reassembly | Fragmented probes (`nmap -f`) are not parsed as TCP | Reassembly or a fragment-anomaly detector (Phase 10) |

## 6. Real captures

*Not yet measured.* This section will hold the results of roadmap Phase 2
(UTM lab: Kali → Ubuntu) and of public datasets.
