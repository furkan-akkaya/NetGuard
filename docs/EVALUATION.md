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

## 2. Results: synthetic scenarios (v0.2.0, unchanged since v0.1.0)

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
  Phase 3, DHCP correlation in Phase 7).
- The missed slow scan shows the basic trade-off of window-based detection.
  A 60 s window keeps memory low and alerts fast, but an attacker who knows
  the window can stay under it.

## 3. Performance

Hardware: Apple M1 (MacBook Air), 16 GB, macOS. Python 3.11, single process.
Wall time includes interpreter start-up. Each row is 3 consecutive runs on the
same machine and file; variance comes from a busy laptop, not the input.

### Reference capture

`benchmarks/make_bench_pcap.py` writes a deterministic 242 003-frame capture:
20 000 benign TCP connections (handshake, 3 request/response pairs, FIN close)
plus one 1000-port SYN scan.

```bash
uv run python benchmarks/make_bench_pcap.py /tmp/bench.pcap
/usr/bin/time -l uv run netguard analyze -f json /tmp/bench.pcap > /dev/null
```

| Version | Wall time | Max RSS | Throughput (incl. start-up) |
|---|---:|---:|---:|
| v0.1.0 (`main` @ `0b67a4d`) | 3.4–3.9 s | 36 MB | ~62–71k pkt/s |
| v0.2.0, first flow-table version (dpkt decode) | 4.5–5.0 s | 33 MB | ~48–54k pkt/s — **rejected: +28%, over the 20% budget** |
| v0.2.0 (`struct` fast path, ADR-0005) | 2.2 s (one 3.1 s outlier) | 35 MB | ~110k pkt/s |
| v0.2.0 `netguard flows` (export only) | 2.15 s | 31 MB | ~113k pkt/s |

v0.2.0 does strictly more work per packet (flow table, connection state,
sequence tracking, richer statistics) and is still ~1.6× faster than v0.1.0.
Alerts on every lab scenario are identical except for the intentional
incident fix noted in the changelog.

### Worst case: spoofed-source SYN flood

`benchmarks/flood_memory.py` feeds `Packet` objects (no pcap decoding) where
every packet has a new source IP, so every packet is a new flow and a new
detector key. This is the state-exhaustion attack against an IDS.

```bash
uv run python benchmarks/flood_memory.py 500000
```

| Version | 100k packets | 500k packets |
|---|---|---|
| Before the tracker fixes (flow table already bounded) | 519 MB peak RSS | did not finish in 120 s (O(max_keys) work per packet once full) |
| v0.2.0 | 219 MB, 1.5 s | 349 MB, 8.7 s (~57k pkt/s); 300 000 flows evicted, endpoint table approximate |

Peak memory is bounded by `[flows] max_flows` (200 000) and the detectors'
`max_keys` (100 000 per detector), not by traffic volume. On the 4 GB Ubuntu
host this worst case uses under 10% of RAM.

For scale: a fully loaded 1 Gbit/s link carries roughly 80k–1.4M packets/s
depending on packet size, so NetGuard is **not** a line-rate sensor. It fits
home and lab networks, low-traffic servers, and offline forensic analysis.

## 4. Robustness

- **Malformed frames:** `tests/test_decode.py::test_decoder_survives_random_mutation`
  feeds 5 000 randomly mutated and truncated frames through the decoder. It
  must never raise. `test_fast_path_matches_dpkt_path` checks that the `struct`
  fast path and dpkt produce identical packets for every frame the fast path
  accepts (>1000 of 5 000 mutants).
- **Malformed capture files:** `tests/test_formats.py` covers hostile length
  fields (pcap `caplen = 0xFFFFFFFF`, pcapng block lengths that are too small,
  unaligned or over 16 MiB), packets referencing undefined interfaces,
  truncated tails (reported, not fatal) and unsupported link types (counted,
  not fatal).
- **Memory bounds:** per-key event caps, key-count caps with O(1) LRU eviction,
  flow-table cap with O(1) expiry and eviction, bounded endpoint statistics and
  time series. When a cap is hit, NetGuard degrades to *missed detections*
  (fail-open), counts it in the output, and never grows without bound.

## 5. Known limitations (v0.2.0)

| Limitation | Impact | Planned fix |
|---|---|---|
| Fixed 60 s window | Slow scans evade detection | Long-horizon detector (3.4) |
| Outcome-blind counting | Bursts of successful connections (passive FTP, some P2P) look like scans | TRW using Phase 2 flow states (3.2) |
| No UDP scan detection | `nmap -sU` is invisible | UDP scan detector (3.3) |
| ARP: one change = alert | DHCP re-assignment and VRRP failover raise MEDIUM alerts | DHCP/lease correlation, flip-flop-only mode (Phase 7) |
| Spoofed source IPs | Decoy scans (`nmap -D`) split one scan into many sources | Target-centric correlation (Phase 7) |
| Idle-timeout reporting | Live alerts arrive ≥ 10 s after the scan pauses | Early-warning alerts (6.4) |
| No IP fragment reassembly | Fragmented probes (`nmap -f`) are not parsed as TCP; fragments are now flagged and counted | Fragment-anomaly rule (3.10) or reassembly (Phase 7) |
| Flow orientation without a SYN | Mid-stream flows keep the first sender as originator | Port heuristics only if lab data shows the need |
| Retransmission vs. reordering | Late out-of-order segments are counted as retransmissions | Inherent to passive observation; documented (ADR-0004) |

## 6. Real captures

*Not yet measured.* This section will hold the results of roadmap Phase 8
(UTM lab: Kali → Ubuntu, [LAB_SETUP.md](LAB_SETUP.md)) and of public datasets.
