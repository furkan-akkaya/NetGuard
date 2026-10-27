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

## 2. Results: synthetic scenarios (v0.7.0)

| Scenario | Type | Packets | Alerts | TP | FP | FN | Outcome | Note |
|---|---|---:|---:|---:|---:|---:|---|---|
| `benign_office` | benign | 462 | 0 | 0 | 0 | 0 | quiet (correct) |  |
| `monitoring_poller` | benign | 180 | 3 | 0 | 1 | 0 | false positive | Expected false positive with default config: indistinguishable from a ping sweep by rate alone. |
| `monitoring_poller_allowlisted` | benign | 180 | 0 | 0 | 0 | 0 | quiet (correct) |  |
| `dhcp_reassignment` | benign | 2 | 1 | 0 | 1 | 0 | false positive | Expected false positive: no DHCP visible, a single binding change cannot be told apart from spoofing. |
| `dhcp_reassignment_seen` | benign | 4 | 0 | 0 | 0 | 0 | quiet (correct) | DHCP lease correlation explains the change (ADR-0011). |
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
| `compromised_workstation` | attack | 582 | 4 | 4 | 0 | 0 | detected | Multi-stage: correlation groups the four alerts into one incident (C2, Discovery, Defense Evasion). |
| `arp_spoof_with_rogue_dhcp` | attack | 14 | 1 | 1 | 0 | 0 | detected | A forged DHCP ACK from an untrusted server does not explain the change. |
| `udp_scan` | attack | 204 | 1 | 1 | 0 | 0 | detected |  |
| `syn_flood_spoofed` | attack | 12000 | 1 | 1 | 0 | 0 | detected |  |
| `dns_tunnel` | attack | 300 | 1 | 1 | 0 | 0 | detected |  |
| `dga_nxdomain` | attack | 120 | 1 | 1 | 0 | 0 | detected |  |
| `connection_burst` | attack | 4500 | 1 | 1 | 0 | 0 | detected |  |
| `exfil_volume` | attack | 25159 | 1 | 1 | 0 | 0 | detected |  |

**Totals:** TP=20, FP=3, FN=1 — precision 0.87, recall 0.95 (entity level, synthetic scenarios).

**Scenarios:** 15/15 attack scenarios detected by at least one expected rule; 9/12 benign scenarios without false positives.

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
  poller (allowlist), DHCP re-assignment *without visible DHCP* (with the DHCP
  ACK visible it is explained since v0.7: `dhcp_reassignment_seen`), a wrong
  DNS search suffix (one domain, readable names). All three score **low
  confidence** (25–30) while every true positive scores 45–95 — see
  [CONFIDENCE.md](CONFIDENCE.md) for why this is a consistency check rather
  than an accuracy claim.
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
| `compromised_workstation` | NG-DNS-001 | `10.0.0.20` | 20.4 s | early | 70.2 s |
| `compromised_workstation` | NG-FRAG-001 | `10.0.0.20` | 1.2 s | early | 70.2 s |
| `compromised_workstation` | NG-SCAN-001 | `10.0.0.20->10.0.0.10` | 0.6 s | early | 70.2 s |
| `compromised_workstation` | NG-SCAN-002 | `10.0.0.20` | 0.6 s | early | 70.2 s |
| `arp_spoof_with_rogue_dhcp` | NG-ARP-001 | `10.0.0.1` | 0.0 s | final | 88.0 s |
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

## Confidence and correlation (v0.7.0)

| Measure | Value |
|---|---|
| True-positive alerts, confidence | 22 alerts, 45–95 |
| False-positive alerts, confidence | 5 alerts, 25–30 (all `low`) |
| Alerts → incidents, attack scenarios with several alerts | `syn_scan_1000` 2 → 1, `arp_spoof_mitm` 4 → 1, `compromised_workstation` 4 → 1 (3 ATT&CK tactics) |

Method and factor justifications: [CONFIDENCE.md](CONFIDENCE.md). Reproduce
with `netguard analyze -f json` (each alert's `confidence`, the document's
`incidents`).

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
| v0.8.0 + Phase 10 changes (11 rules, confidence, correlation) | 2.47–2.48 s | 34 MB | ~98k pkt/s |

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
| v0.8.0 + Phase 10 (11 rules, Apple M1, Python 3.11) | 263 MB, 2.3 s | 469 MB, 11.7 s (~43k pkt/s) |

Peak memory is bounded by `[flows] max_flows` (200 000) and each rule's key
limit (`max_keys`, `max_sources`, `max_targets`), not by traffic volume. On the
4 GB Ubuntu host the v0.3.0 worst case uses about 12% of RAM; lowering
`max_flows` and the per-rule limits shrinks it further.

What the flood costs in detection (measured in Phase 10, 500k packets): the
flood itself is detected (one final NG-SYN-001 alert; its state is keyed by
target, so it does not fill up), but the per-source tables of other rules
overflow and drop state: portscan and hostsweep 400 000 keys each, TRW
450 000 sources, the connection-rate and volume baselines 490 000 hosts each.
A real scan hidden inside such a flood can therefore be missed. Since Phase 10
the output says so (`stats.detectors`, a warning in the text output, the HTML
report and the dashboard) instead of only counting it internally.

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

## 5. Known limitations (reviewed in Phase 10)

Detection limitations. Each rule page lists its own false positives and
negatives in more detail.

| Limitation | Impact | Status |
|---|---|---|
| Window rule (NG-SCAN-001) has a fixed 60 s window | Slow scans evade it | Mitigated: TRW (NG-SCAN-002) detects them up to its 1 h state horizon (`slow_scan`) |
| TRW needs SYN-based probes | NULL/FIN/XMAS scans are only seen by the window rule | By design |
| UDP scans and ICMP rate limiting | Closed UDP ports often look silent | The rule does not depend on ICMP replies; they are evidence only |
| Baseline rules need warm-up | No rate/volume alerts in captures shorter than 10 min; baselines are per analysis, not kept between analyses | Open (seasonal/persistent baselines deferred, ADR-0011) |
| DNS over HTTPS/TLS | Tunnels and DGA lookups inside DoH/DoT are invisible | Out of scope (encrypted) |
| Registered-domain heuristic | Names under multi-level public suffixes may be grouped one level too high | Open (no Public Suffix List, to avoid a download/dependency) |
| ARP without visible DHCP | A re-assigned IP or a VRRP/HSRP failover raises a MEDIUM alert (`dhcp_reassignment`, low confidence) | Mitigated when the DHCP ACK is in the capture (ADR-0011); a rogue DHCP server answering first is trusted (TOFU, configure `dhcp_servers`) |
| Decoy scans with spoofed sources (`nmap -D`) | One scan becomes many small ones per source, each possibly below threshold | Open: correlation groups by actor, not by target |
| Spoofed-source floods | Per-source detector tables overflow: a real scan inside such a flood can be missed (§3) | Reported since Phase 10 (`stats.detectors`, warnings) |
| No IP fragment reassembly | Probes inside fragments (`nmap -f`) are not analysed; NG-FRAG-001 reports the evasion itself. On the real exp09 capture the 100 probed connections appear reversed (starting at the victim's reply) and as `OTH`, where Zeek reassembles and reports `REJ`/`RSTO` (§ 6). IPv6 fragments and DHCPv6 not inspected | Open; reassembly only if lab data shows the need |
| Flow orientation without a SYN | Mid-stream flows keep the first sender as originator (as Zeek does); their states follow Zeek's endpoint rules (checked on real NULL/FIN/Xmas scans, § 6) | Open; documented (ADR-0004) |
| Retransmission vs. reordering | Late out-of-order segments are counted as retransmissions | Inherent to passive observation (ADR-0004) |
| Live alert latency | In the synthetic replay benchmark, early warnings arrive 1–2 s after a threshold is crossed; rules with intervals add their interval (§2, detection delay). Live, one run: 0.68-0.76 s after the threshold-crossing packet for the two scan rules (§6, live-early-01) | By design (ADR-0010) |
| Throughput | ~100k packets/s offline on an M1; not a line-rate sensor (§3) | By design: home/lab networks, low-traffic servers, forensics |
| Confidence scores | Factors and scenarios come from the same author; separation is a consistency check, not accuracy | Must be re-checked on real lab captures (Phase 8) |

## 6. Real captures

**Real captures measured so far (27 Oct 2026)**: two SYN scans, one
analysed offline (exp01) and one captured live by `netguard monitor` on the
victim's lab interface (live-syn-01), one hour of live benign traffic
(benign-01), and eight further scan experiments (exp02-exp05, exp07-exp10,
last section). All on an isolated two-VM UTM lab (Kali 10.77.0.10 -> Ubuntu
10.77.0.20). Each experiment is one run of one tool configuration: the
results say the declared rule fired with the declared entity on that capture,
not what precision or recall NetGuard has in general. Later the same day the
slow scan (exp06), the ARP and DNS experiments (exp11-exp13) and the live
early-warning run (live-early-01) followed (last sections). The baseline
experiment (exp14) is not measured yet.

Provenance and integrity: the capture bytes are hash-verified
(SHA-256 `376d4b6c…bbbd93a9`, matched on the capture host and the Mac). This
first capture was taken by hand, so the command, nmap version and tcpdump
counts come from the operator's own report/screenshots, not from the capture
scripts; later experiments use `eval/lab/` and record their own metadata. The
capture is **not** traffic-free: besides the scan it contains 4 SSDP multicast
packets (192.168.128.1 -> 239.255.255.250:1900) from the UTM host side of the
shared network. The lab has no routed internet, but it is not silent.

### exp01 — `sudo nmap -sS -Pn -n -p 1-1000 --max-retries 1 --max-rate 100`

| Measure | Result |
|---|---|
| Frames / decode errors | 2009 / 0 |
| Flow states | REJ 999, RSTO 1, S0 1 |
| Ground truth (declared first) | `portscan` 10.77.0.10->10.77.0.20, `trw` 10.77.0.10 |
| Detected | both; TP 2, **FP 0**, FN 0 (the 4 SSDP packets raised nothing) |
| NG-SCAN-001 | 1000 distinct ports in 10.0 s, 1 open (22), 999 closed; confidence 90 |
| NG-SCAN-002 (TRW) | 1000 first contacts, 999 rejected, 1 succeeded; threshold crossed; confidence 95 |
| No detector dropped state | all `evicted_*` / `untracked_*` zero |

Reproduce: `python3 eval/lab/ingest.py <transfer-dir>` then
`uv run netguard lab evaluate --manifest eval/captures.toml`. One attack
capture cannot establish precision/recall for the tool; it shows the two scan
rules fire on a real nmap SYN scan with the declared entities and no false
positive on this capture.

### Flow states vs Zeek (same capture)

Compared with a real **Zeek 8.2.2** `conn.log` of the same file (network
disabled, checksum validation on): **1001 of 1001** directional TCP/UDP flows
matched on endpoints, direction and connection state, with **zero**
differences (`netguard lab compare-flows`, reproduced on the Mac). This checks
flow reconstruction against an independent tool on real traffic, not full Zeek
semantic compatibility.

### Replay vs offline (same capture)

Replaying the capture through the live pipeline (`netguard replay --speed 0`)
produced the **same two final alerts** as offline analysis
(`eval/lab/live_offline_equal.py`, equal). This exercises the live code path
but is not a live-interface measurement; that is the next section.

### live-syn-01 — live capture on the victim's interface

The same scan (`nmap -sS`, 1000 ports, `--max-rate 100`) captured live by
`netguard monitor --sudo --duration 90 --no-early-warning` on the Ubuntu VM
(NetGuard as a normal user, tcpdump via sudo; built from commit `a845dea`),
which also wrote the pcap. Capture SHA-256 `65533b5b…3ff3ffce`, live JSONL
SHA-256 `f1f7493a…605d98cb`, both verified on the Mac.

| Measure | Result |
|---|---|
| Run (monitor summary on the VM, operator report) | 90.3 s; kernel captured 2005, received by filter 2005, **dropped 0**; 144 330 bytes written |
| Capture (re-analysed on the Mac) | 2005 frames (2001 TCP, 4 ARP), 0 decode errors; REJ 999, RSTO 1 |
| Live final alerts | NG-SCAN-001 and NG-SCAN-002 |
| **Live vs offline** | the same two final alerts; every field identical except `reported_at` (`live_offline_equal.py` equal) |
| **Flow states vs Zeek 8.2.2** | **1000 of 1000** flows matched on endpoints, direction and state, zero differences |

Reporting delay: with early warnings switched off, an alert is reported only
when its incident closes. Live, NG-SCAN-001 was reported 11.0 s and
NG-SCAN-002 50.2 s after the last scan packet (21.0 s and 60.2 s after the
first); offline, both are closed at the last packet because the file ends
there. So the 60.2 s maximum is the incidents' closing time, not processing
lag. The delay **with** early warnings has not been measured live; the
synthetic replay benchmark (§ 2, detection delay) suggests 1-2 s for a scan
like this, but that is an estimate until a live run confirms it.

Zeek logged a warning that the trace contains only TCP control packets
(expected for a SYN scan without payloads). One live run of one attack type
shows the live path, kernel-drop accounting and live/offline agreement work
on real traffic; it is not a resource or long-run measurement (that is
benign-01, below).

### benign-01 — one hour of live benign traffic

`netguard monitor --sudo --duration 3640` on the Ubuntu VM's lab interface
(`eval/lab/victim-live-rss.sh`, NetGuard as a normal user, default
configuration, early warnings on) while `eval/lab/kali-benign.sh 3600` on Kali
sent paced client traffic: one cycle every 4-9 s of a ping and a TCP connect
to SSH port 22 that reads the server banner. NetGuard was the `netguard-lab.pyz`
build of commit `a845dea`; the two runner scripts are byte-identical to the
ones in `eval/lab/` (SHA-256 `31118e1b…` and `fee45b8a…`). This is a run of
that build, not of later commits. The five result files (pcap, live JSONL,
monitor output, RSS samples, metadata) were transferred and their SHA-256
values checked on the Mac against the list written on the VM; pcap
`f3c6a7f9…f0e7b849`.

| Measure | Result |
|---|---|
| Run | monitor: duration reached after 3640.1 s; runner's monotonic clock 3641 s; monitor exit status 0 |
| Kernel counters (from the monitor's summary line) | captured 4245, received by filter 4245, **dropped 0**; pcap not truncated, 421 579 bytes |
| Capture (re-analysed on the Mac) | 4245 packets over 3608.7 s (first to last packet), 0 decode errors; TCP 3415, ICMP 750, UDP 80; 398 flows (376 SSH, 1 ICMP echo flow, 20 multicast UDP, 1 rejected TCP/80) |
| **Final alerts** | **live 0, offline 0** (`live_offline_equal.py` equal; the live JSONL is empty, so not even an early warning); offline re-analysis used the current source, whose `src/` is unchanged since `a845dea`; no incidents; no detector reported lost state (all `evicted_*` / `untracked_*` zero) |
| Analyser memory | 724 RSS samples, one every 5 s; first 34 488 KiB, last 30 104 KiB, highest 34 812 KiB (34.0 MiB) |

What the traffic was, from the capture rather than the script: 376 SSH
connections from Kali, 375 of which carry only the server's 42-byte banner
(the client sends nothing) and one, starting before the generator, a full SSH
exchange with payload in both directions; 375 ICMP echo request/reply pairs;
one connection attempt to TCP/80, refused (the generator's one-time check for
a web server; the victim runs none, so no HTTP followed). The UDP flows are
all multicast that nobody answers: SSDP (UDP/1900) and mDNS (UDP/5353) from
192.168.128.1 and an IPv6 link-local address, and the victim's own mDNS. So
the lab interface is not traffic-free, and part of the "benign" traffic is
the host's own discovery noise.

Memory: the series rises from 34 488 to 34 812 KiB in the first two minutes,
holds there until about 9.5 minutes into the run, then falls and stays
between 28 808 and 32 564 KiB for the rest of the run. The peak is the highest
5-second sample; VmHWM agreed with it, then later read 34 608 KiB. The kernel
updates that figure lazily, so it can fall, and a short peak between two
samples could be missed.

Flow states vs **Zeek 8.2.2** (`conn.log` of the same pcap, network disabled,
checksum validation on). With the source as it was for the run (`a845dea`),
**396 of 397** NetGuard TCP/UDP flows matched (397 NetGuard, 399 Zeek); the
operator reproduced this independently with the official Zeek 8.2.2 image.
`compare-flows` reported two differences:

- **mDNS flow split (explained, a timeout setting).** Zeek splits the mDNS
  traffic from 192.168.128.1 and from an IPv6 link-local address into five
  connections each, NetGuard into four: two packet bursts 46.7 s apart are one
  flow for NetGuard (UDP idle timeout 60 s) and two for Zeek, which applies
  `dns_session_timeout` (10 s) to traffic its DNS analyser handles. With
  `dns_session_timeout=60sec` Zeek also produces four, and only the next
  difference remains.
- **One SSH connection classed differently (NetGuard's state rule).** In
  10.77.0.10:40076 -> 10.77.0.20:22 both sides sent FIN, then the client sent
  two RSTs. Zeek reports SF (closed normally; history `ShAFadfR`), NetGuard
  RSTO, because its state function checked RST before a FIN exchange. This
  was a real semantic difference from Zeek, not a capture artefact. **Fixed**
  (task 8.14): NetGuard now follows Zeek's endpoint rules for the order of
  FIN and RST (ADR-0004), with a regression test reduced from this
  connection and 14 orderings each checked against Zeek 8.2.2.

After the fix, on the same pcap: **397 of 397** NetGuard TCP/UDP flows match
Zeek's (399 Zeek flows: only the two extra mDNS splits remain), and with
`dns_session_timeout=60sec` the comparison is **equal (397/397)**. The mDNS
split is a design parameter, not an error: NetGuard uses one UDP idle timeout
(60 s, Zeek's `udp_inactivity_timeout`) for every UDP flow and has no shorter
DNS-specific session timeout. The two SYN-scan captures still match Zeek
exactly after the fix (1001/1001 and 1000/1000), and their alerts are
unchanged. A later change made the state of connections that **both** sides reset follow Zeek too (task 8.15); none of the three captures has such a connection, and `eval/lab/real_regression.py --zeek` pins all three results (packets, flows, states, final alerts, Zeek equality). The flow-state fix changes no alert in any of the three captures;
the live run itself was not repeated with the fixed build.

Zeek also logged one `bad_TCP_checksum` packet (in the first SSH session);
running Zeek with `-C` (checksums ignored) gives the same comparison.

What this shows, and what it does not:

- On this one hour of low-rate SSH-banner and ping traffic with multicast
  background, NetGuard raised no alert live or offline, lost no packets in
  the kernel, and peaked at 34.0 MiB. The LAB_SETUP criteria "benign noise"
  (≤ 1 final alert per hour) and "resources" (RSS below 500 MB, no state-loss
  warnings) are met **for this scenario**.
- It is not a false-positive rate for real networks: one host pair, 1.2
  packets/s on average, almost no payload, no web, DNS, file transfer or
  user activity. It says nothing about memory under high traffic or over days
  (the synthetic worst cases are in § 3).
- UDP was compared with Zeek only as one-way multicast; there was no UDP
  request/response traffic. SSH payload was compared only as far as flow
  states go.

The tooling behind these: `netguard lab evaluate --manifest`, `compare-flows`,
and the lab scripts in `eval/lab/` ([CAPTURE_EVALUATION.md](CAPTURE_EVALUATION.md),
[LAB_SETUP.md](LAB_SETUP.md)).

### exp02-exp10 — scans run by the lab bridge

Run on 27 Oct 2026 by a fixed-action bridge on the two lab VMs, with the lab
kit built from commit `8a7f181` (`BUILD.json`; the kit's `SHA256SUMS` verified
on the Mac). Every capture's files were hash-checked on the Mac against the
manifest written on the capture host. The bridge itself talks over the lab
network: HTTP between the VMs on TCP 8766 (jobs and uploads, on
10.77.0.20) and, from exp06 on, TCP 8767 as well. Those control connections
are **in the captures** of exp05 onwards (21-24 `SF` flows each in exp05,
exp07-exp10; far more in the later, longer captures), and raised no alert. They carry an access
token in clear text, so these captures are not shareable as they are (they
stay out of git like every capture), and the token should be rotated.

| Capture | Tool (Kali) | Packets / kernel drops | Final alerts (declared entity) | Flows vs Zeek 8.2.2 |
|---|---|---|---|---|
| exp02-connect-scan-r02 | `nmap -sT -p 1-1000 --max-parallelism 1` | 2006 / 0 | NG-SCAN-001, NG-SCAN-002 | 1000/1000 equal |
| exp03-xmas-scan | `nmap -sX -p 1-1000 --scan-delay 10ms` | 2004 / 0 | NG-SCAN-001 | 1001/1001 equal (after the fix below) |
| exp04-fin-scan | `nmap -sF -p 1-1000 --scan-delay 10ms` | 2008 / 0 | NG-SCAN-001 | 1003/1003 equal (after the fix) |
| exp05-null-scan | `nmap -sN -p 1-1000 --scan-delay 10ms` | 2230 / 0 | NG-SCAN-001 | 1023/1023 equal (after the fix) |
| exp07-udp-scan | `nmap -sU --top-ports 100` | 478 / 0 | NG-SCAN-003 | 214/214 equal |
| exp08-ping-sweep | `nmap -sn --max-rate 100 10.77.0.0/24` | 798 / 0 | NG-SWEEP-001 | 24/24 equal |
| exp09-frag-scan | `nmap -sS -f -p 1-100 --scan-delay 10ms` | 632 / 0 | NG-FRAG-001 | 23 equal, 100 differ: design limit |
| exp10-syn-burst | `hping3 -S -p 9 -i u10000 -c 1500` (closed port, 100/s) | 3240 / 0 | NG-SYN-001 | 1523/1523 equal |

Each experiment raised exactly its declared detections (detector and entity
from `experiments.toml`, written before the runs) and no other alert. The first
exp02 run is not counted: tcpdump dropped 438 of 2010 packets, and the
experiment was repeated with `--max-parallelism 1` (r02, 0 drops).

**A flow-state bug found by these captures.** NULL, FIN and Xmas probes carry
no SYN. NetGuard called every such connection `OTH`; Zeek applies its endpoint
states anyway and reports `RSTRH` for a NULL probe answered by RST, `RSTR` for
a FIN or Xmas probe answered by RST, and `SH` for an unanswered FIN probe
(999 + 2 differences in each capture). NetGuard now follows Zeek's rules
(ADR-0004 rule 3), checked case by case against Zeek 8.2.2 and with a
regression test reduced from the real probes. The labels reach no detector
(TRW counts only first contacts opened by a SYN), and the alerts of all eleven
pinned captures are unchanged.

**exp09: a design limit, not a bug.** `nmap -f` splits each SYN into three
8-byte IP fragments; the TCP flags are in the second. NetGuard does not
reassemble fragments, so the probe is not a TCP segment to it and each of the
100 probed connections starts at the victim's reply: reversed direction,
state `OTH`. Zeek reassembles and reports 99 `REJ` and 1 `RSTO`. NG-FRAG-001
reports the fragmentation itself; the scan rules do not see these probes.
The difference is pinned by size in `real-regression.toml`, so it can neither
grow nor disappear unnoticed.

The VMs ran the `8a7f181` build, which still had the old `OTH` labels; the
fix changes no alert, and the offline re-analysis with the fixed code is what
the table reports. `eval/lab/real_regression.py --zeek` pins all eleven
captures.


### exp06, exp11-exp13 — slow scan, ARP and DNS

Same bridge and kit (`8a7f181`), same checks (hash manifests verified on the
Mac, ground truth from `experiments.toml`, Zeek 8.2.2 with checksums on).
From exp06 on the bridge also uses TCP 8767, so these captures hold control
connections on 8766 and 8767; they raised no alert.

| Capture | Tool | Packets / kernel drops | Final alerts | Flows vs Zeek 8.2.2 |
|---|---|---|---|---|
| exp06-slow-scan | `nmap -sS -T1 -p 1-50 --max-retries 1` (825.95 s) | 3985 / 0 | NG-SCAN-002 (declared: TRW only; the window rule is not expected at this rate) | 435/435 equal |
| exp11-arp-binding | `kali_arp_binding.py`: gratuitous ARP for the unused 10.77.0.99, 3 frames from one MAC, then 3 from another | 645 / 0 | NG-ARP-001, 10.77.0.99 | 62/62 equal (TCP/UDP; ARP is not in `conn.log`) |
| exp12-dns-nxdomain | `victim_dns_queries.py nxdomain`: 40 queries, 40 NXDOMAIN replies | 857 / 0 | NG-DNS-002, 10.77.0.20 | 79/79 equal |
| exp13-dns-tunnel | `victim_dns_queries.py tunnel`: 80 queries with 32-character labels, 40 s | 11517 / 0 | NG-DNS-001, 10.77.0.20 | equal with `tcp_attempt_delay=30sec` (below) |

Each raised exactly its declared detection and no other alert. exp13's
capture ran about 14 minutes although the queries took 40 s: the bridge's
control script was being changed meanwhile. The packets after the queries are
control traffic on 8766/8767 (10863) and 12 multicast packets; they raised no
alert. With Zeek's defaults exp13 differs by 55 flows, all unanswered SYN
attempts to the control port 8766: Zeek closes an attempt after
`tcp_attempt_delay` (5 s) and logs the retransmitted SYNs as new connections,
NetGuard keeps SYN retransmissions in one flow for its 30 s handshake
timeout. With `tcp_attempt_delay=30sec` the comparison is equal. This is a
timeout parameter, like the DNS session timeout in benign-01, not an error.

### live-early-01 — live early-warning delay

Live run on the victim's interface (`victim-live-rss.sh live-early-01 120`,
`monitor --sudo`, early warnings on, `8a7f181` build) while Kali ran
`nmap -sS -Pn -n -p 1-1000 --scan-delay 10ms --max-retries 1`. 123 s
(monotonic), 4263 packets, 0 kernel drops, peak RSS 36292 KiB (VmHWM).
2 early warnings and 2 final alerts (NG-SCAN-001, NG-SCAN-002, declared
entities); the final alerts equal the offline analysis of the written pcap in
every field except `reported_at` (`live_offline_equal.py`); flows equal to
Zeek (1225/1225).

| Early warning | Reported after the threshold-crossing packet | Newest evidence age at report | After the incident's first packet |
|---|---|---|---|
| NG-SCAN-001 | 0.683 s | 0.011 s | 5.135 s |
| NG-SCAN-002 (TRW) | 0.757 s | 0.011 s | 5.135 s |

How these were measured: `live_delay.py --pcap` replays the written capture
through the same detectors, ticking after every packet, and takes the packet
after which each early warning opened. For NG-SCAN-001 that is the 15th
distinct destination port from 10.77.0.10 to 10.77.0.20, counting the two
control ports 8766 and 8767 the detector also counts (without them the 15th
scan port came 21 ms later); for TRW it is the decision time in the alert's
own evidence (`decided_at_seconds` after `first_seen`). Both agree with an
independent calculation from the pcap. The 0.011 s column is only how old the
newest packet of the incident was when the report went out: the incident keeps
growing between the threshold crossing and the next one-second tick, so it is
not a threshold delay. The incident's first packet is a control connection
that started 4.3 s before the scan, so the last column is not time since the
scan began either. One run, one scan type, one host pair: it shows the live
path reports within the one-second tick on this lab, not a latency guarantee.
