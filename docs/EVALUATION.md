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
| `portscan`, `udpscan` | `scanner->target` |
| `hostsweep`, `trw`, `fragments` | `scanner` |
| `dnstunnel`, `nxdomain`, `connrate`, `volume` | client / source host |
| `synflood` | target host |
| `arpspoof` | hijacked IP |

An attack scenario counts as **detected** when at least one of its expected
`(rule, entity)` pairs fired (e.g. a slow scan seen by TRW but not by the window rule).

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

## 2. Results: synthetic scenarios (v0.3.0)

| Scenario | Type | Packets | Alerts | TP | FP | FN | Outcome | Note |
|---|---|---:|---:|---:|---:|---:|---|---|
| `benign_office` | benign | 462 | 0 | 0 | 0 | 0 | quiet (correct) |  |
| `monitoring_poller` | benign | 180 | 3 | 0 | 1 | 0 | false positive | Expected false positive with default config: indistinguishable from a ping sweep by rate alone. |
| `monitoring_poller_allowlisted` | benign | 180 | 0 | 0 | 0 | 0 | quiet (correct) |  |
| `dhcp_reassignment` | benign | 2 | 1 | 0 | 1 | 0 | false positive | Expected false positive (MEDIUM): a single binding change cannot be told apart from spoofing. |
| `passive_ftp` | benign | 266 | 0 | 0 | 0 | 0 | quiet (correct) | Every connection succeeds: the window rule suppresses it (max_open_ratio), TRW sees only successes. |
| `flash_crowd` | benign | 6400 | 0 | 0 | 0 | 0 | quiet (correct) | SYN-flood look-alike |
| `voip_call` | benign | 200 | 0 | 0 | 0 | 0 | quiet (correct) | UDP-scan look-alike |
| `cdn_lookups` | benign | 160 | 0 | 0 | 0 | 0 | quiet (correct) | DNS-tunnel look-alike |
| `search_suffix_nxdomain` | benign | 60 | 1 | 0 | 1 | 0 | false positive | Expected false positive: indistinguishable from DGA by count; evidence shows one domain, readable names. |
| `fragmented_udp` | benign | 60 | 0 | 0 | 0 | 0 | quiet (correct) | Fragmentation look-alike |
| `growing_workload` | benign | 6870 | 0 | 0 | 0 | 0 | quiet (correct) | Connection-rate look-alike: the baseline adapts to gradual growth. |
| `syn_scan_1000` | attack | 2003 | 2 | 2 | 0 | 0 | detected |  |
| `xmas_scan` | attack | 398 | 1 | 1 | 0 | 0 | detected |  |
| `slow_scan` | attack | 201 | 1 | 1 | 0 | 1 | detected (partly) | Window rule misses it (at most 5 probes per 60s, threshold 15); TRW has no window and detects it. |
| `ping_sweep` | attack | 259 | 1 | 1 | 0 | 0 | detected |  |
| `arp_sweep` | attack | 259 | 1 | 1 | 0 | 0 | detected |  |
| `arp_spoof_mitm` | attack | 70 | 4 | 2 | 0 | 0 | detected |  |
| `fragmented_scan` | attack | 150 | 1 | 1 | 0 | 0 | detected | Probes themselves are invisible to the scan rules (no reassembly); the fragmentation is detected. |
| `udp_scan` | attack | 204 | 1 | 1 | 0 | 0 | detected |  |
| `syn_flood_spoofed` | attack | 12000 | 1 | 1 | 0 | 0 | detected |  |
| `dns_tunnel` | attack | 300 | 1 | 1 | 0 | 0 | detected |  |
| `dga_nxdomain` | attack | 120 | 1 | 1 | 0 | 0 | detected |  |
| `connection_burst` | attack | 4500 | 1 | 1 | 0 | 0 | detected |  |
| `exfil_volume` | attack | 25159 | 1 | 1 | 0 | 0 | detected |  |

**Totals:** TP=15, FP=3, FN=1 — precision 0.83, recall 0.94 (entity level, synthetic scenarios).

**Scenarios:** 13/13 attack scenarios detected by at least one expected rule; 8/11 benign scenarios without false positives.

### How to read this

- These numbers measure **the logic against scenarios we designed**, and the
  same person designed the rules and the scenarios. Read them as a
  regression-tested specification ("this rule fires on this behaviour and not
  on that look-alike"), not as accuracy on real networks. Real traffic is
  messier: retransmissions, NAT, scanners with jitter and decoys, chatty IoT
  devices.
- Each new rule comes with at least one attack and one **benign look-alike**
  (flash crowd for SYN flood, VoIP for UDP scan, CDN lookups for DNS tunnel,
  MTU fragmentation for fragment evasion, gradual growth for connection rate).
- The three false positives are **known and explained**: the monitoring
  poller (allowlist today, baselining in Phase 7), DHCP re-assignment (DHCP
  correlation in Phase 7), a wrong DNS search suffix (the evidence shows one
  domain with readable names; no automatic fix planned yet).
- The remaining FN is the window rule on `slow_scan`; TRW detects the same
  scenario, so the scenario counts as detected.
- `benign_office` was made more realistic in v0.3: its 40 HTTPS connections
  now complete. Before, they were SYNs that never got an answer, which no
  real browsing session produces and which TRW correctly treated as 40 failed
  connections. This changes test data, so it is recorded here and in the
  changelog.
- The baseline rules (NG-RATE-001, NG-VOL-001) need 10 minutes of history;
  their scenarios are 16–20 minutes long for that reason.

## Detection delay

How long after an attack starts does its first alert appear? Each attack
scenario is run as `netguard monitor` would see it: early warnings on, and the
engine clock ticking every second even when no packet arrives. Delay =
first alert's `reported_at` − the incident's `first_seen` (ADR-0010).

```bash
uv run python benchmarks/detection_delay.py
```

| Scenario | Rule | Entity | Detected after | First alert | Traffic duration |
|---|---|---|---:|---|---:|
| `syn_scan_1000` | NG-SCAN-001 | `10.0.0.66->10.0.0.10` | 2.0 s | early | 1.0 s |
| `syn_scan_1000` | NG-SCAN-002 | `10.0.0.66` | 2.0 s | early | 1.0 s |
| `xmas_scan` | NG-SCAN-001 | `10.0.0.66->10.0.0.10` | 1.4 s | early | 0.4 s |
| `slow_scan` | NG-SCAN-001 | `10.0.0.66->10.0.0.10` | not detected | - | 1485.0 s |
| `slow_scan` | NG-SCAN-002 | `10.0.0.66` | 76.0 s | early | 1485.0 s |
| `ping_sweep` | NG-SWEEP-001 | `10.0.0.66` | 1.0 s | early | 1.0 s |
| `arp_sweep` | NG-SWEEP-001 | `10.0.0.66` | 1.5 s | early | 0.5 s |
| `arp_spoof_mitm` | NG-ARP-001 | `10.0.0.1` | 0.0 s | final | 68.0 s |
| `arp_spoof_mitm` | NG-ARP-001 | `10.0.0.20` | 0.0 s | final | 68.0 s |
| `fragmented_scan` | NG-FRAG-001 | `10.0.0.66` | 1.5 s | early | 0.5 s |
| `udp_scan` | NG-SCAN-003 | `10.0.0.66->10.0.0.10` | 1.0 s | early | 2.0 s |
| `syn_flood_spoofed` | NG-SYN-001 | `10.0.0.10` | 11.0 s | early | 6.0 s |
| `dns_tunnel` | NG-DNS-001 | `10.0.0.20` | 20.4 s | early | 119.6 s |
| `dga_nxdomain` | NG-DNS-002 | `10.0.0.20` | 13.0 s | early | 29.5 s |
| `connection_burst` | NG-RATE-001 | `10.0.0.20` | 60.8 s | early | 954.9 s |
| `exfil_volume` | NG-VOL-001 | `10.0.0.20` | 60.1 s | early | 951.0 s |

How to read it:

- The engine ticks once per second, so even an instant decision is reported
  with up to ~1–2 s delay (`syn_scan_1000` crosses its threshold after 15 ms).
- Rule design sets the rest: NG-SYN-001 evaluates 10 s intervals (~11 s),
  NG-DNS-001 needs 50 distinct subdomains (20 s at this tunnel's rate),
  NG-SCAN-002 needs ≥ 5 failures and a likelihood-ratio crossing (6 probes
  15 s apart = 76 s), the baseline rules evaluate 60 s intervals (~60 s).
- ARP spoofing is reported at the first conflicting reply (0 s, no early stage).
- Without early warnings, the first alert comes only when the incident closes
  (idle timeout or end of capture): for the slow scan that was 1485 s.

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
| v0.3.0, 11 rules, before protocol dispatch | 2.6–2.7 s | 36 MB | ~90k pkt/s |
| v0.3.0, 11 rules (protocol dispatch, ADR-0006) | 2.45–2.5 s (first run 3.0 s) | 36 MB | ~97k pkt/s |

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
| v0.2.0 (3 rules) | 219 MB, 1.5 s | 349 MB, 8.7 s (~57k pkt/s); 300 000 flows evicted, endpoint table approximate |
| v0.3.0 (11 rules) | 263 MB, 2.3 s | 469 MB, 11.6 s (~43k pkt/s) |

Peak memory is bounded by `[flows] max_flows` (200 000) and each rule's key
limit (`max_keys`, `max_sources`, `max_targets`), not by traffic volume. On the
4 GB Ubuntu host the v0.3.0 worst case uses about 12% of RAM; lowering
`max_flows` and the per-rule limits shrinks it further.

For scale: a fully loaded 1 Gbit/s link carries roughly 80k–1.4M packets/s
depending on packet size, so NetGuard is **not** a line-rate sensor. It fits
home and lab networks, low-traffic servers, and offline forensic analysis.

## 4. Robustness

- **Malformed frames:** `tests/test_decode.py::test_decoder_survives_random_mutation`
  feeds 5 000 randomly mutated and truncated frames through the decoder. It
  must never raise. `test_fast_path_matches_dpkt_path` checks that the `struct`
  fast path and dpkt produce identical packets for every frame the fast path
  accepts (>1000 of 5 000 mutants; seeds include DNS responses, ICMP errors and
  fragments). A one-off campaign of 250 000 mutants per release found no
  mismatch (v0.3.0: 131 536 accepted, 0 mismatches, 0 exceptions). It found
  one during development: a quoted inner IP length smaller than its header,
  which the fast path now declines.
- **Live pipeline:** `tests/test_live.py` runs the monitor pipeline end to end
  with a scripted stand-in for tcpdump (this development machine has no
  capture permission, which also exercised the real permission-denied path),
  checks tcpdump statistics parsing, the pcap write limit, stop/duration
  handling, and that a replay's final alerts equal offline analysis.
- **Malformed DNS:** `tests/test_dns.py` covers compression-pointer loops,
  labels running past the end, reserved label types and names over 255 bytes.
- **Malformed capture files:** `tests/test_formats.py` covers hostile length
  fields (pcap `caplen = 0xFFFFFFFF`, pcapng block lengths that are too small,
  unaligned or over 16 MiB), packets referencing undefined interfaces,
  truncated tails (reported, not fatal) and unsupported link types (counted,
  not fatal).
- **Memory bounds:** per-key event caps, key-count caps with O(1) LRU eviction,
  flow-table cap with O(1) expiry and eviction, bounded endpoint statistics and
  time series. When a cap is hit, NetGuard degrades to *missed detections*
  (fail-open), counts it in the output, and never grows without bound.

## 5. Known limitations (v0.3.0)

| Limitation | Impact | Planned fix |
|---|---|---|
| Window rule (NG-SCAN-001) has a fixed 60 s window | Slow scans evade it | TRW (NG-SCAN-002) covers them up to its 1 h state horizon |
| TRW needs SYN-based probes | NULL/FIN/XMAS scans are only seen by the window rule | — (by design) |
| UDP scans and Linux ICMP rate limiting | Closed UDP ports mostly look silent | Evidence only; the rule does not depend on ICMP |
| Baseline rules need warm-up | No rate/volume alerts in captures shorter than 10 min | Persistent baselines once Phase 4 stores history |
| DNS over HTTPS/TLS | Tunnels and DGA lookups inside DoH/DoT are invisible | Out of scope (encrypted) |
| Registered domain heuristic | Multi-level public suffixes may be keyed one level too high | Optional Public Suffix List (Phase 7) |
| Overlapping alerts | A SYN scan raises NG-SCAN-001 and NG-SCAN-002 | Correlation (Phase 7) |
| ARP: one change = alert | DHCP re-assignment and VRRP failover raise MEDIUM alerts | DHCP/lease correlation, flip-flop-only mode (Phase 7) |
| Spoofed source IPs | Decoy scans (`nmap -D`) split one scan into many sources | Target-centric correlation (Phase 7) |
| Idle-timeout reporting | Live alerts arrive ≥ 10 s after the scan pauses | Early-warning alerts (6.4) |
| No IP fragment reassembly | Probes inside fragments (`nmap -f`) are not analysed; NG-FRAG-001 reports the evasion itself. IPv6 fragments not inspected | Reassembly only if lab data shows the need (Phase 7) |
| Flow orientation without a SYN | Mid-stream flows keep the first sender as originator | Port heuristics only if lab data shows the need |
| Retransmission vs. reordering | Late out-of-order segments are counted as retransmissions | Inherent to passive observation; documented (ADR-0004) |

## 6. Real captures

*Not yet measured.* This section will hold the results of roadmap Phase 8
(UTM lab: Kali → Ubuntu, [LAB_SETUP.md](LAB_SETUP.md)) and of public datasets.
