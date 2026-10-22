# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning: [SemVer](https://semver.org/).

## [0.3.0] - 2026-10-22

Phase 3 (detection engine): eight new rules, each with an attack scenario, a
benign look-alike, unit tests and a rule page.

### Added
- **NG-SCAN-002** `trw`: scan detection by connection outcome (Threshold Random Walk, Jung et al. 2004); catches slow scans the window rule misses.
- **NG-SCAN-003** `udpscan`: UDP port scans with open/closed/filtered evidence from UDP replies and ICMP unreachables.
- **NG-SYN-001** `synflood`: many attempts, few completed handshakes per target, with source-diversity (spoofing) evidence.
- **NG-DNS-001** `dnstunnel`: many long unique subdomains of one registered domain (tunnelling/exfiltration indicators).
- **NG-DNS-002** `nxdomain`: bursts of NXDOMAIN responses (DGA indicator) with domain-spread and entropy evidence.
- **NG-FRAG-001** `fragments`: tiny and header-splitting IPv4 fragments (RFC 1858, `nmap -f`).
- **NG-RATE-001** `connrate` and **NG-VOL-001** `volume`: per-host EWMA baselines of new connections and bytes sent (ADR-0007).
- Connection events from the flow table (`attempt`, `answered`, `rejected`, `established`; UDP first datagram / first reply) and the `on_conn_event` detector hook (ADR-0006).
- Own DNS parser (`dns.py`): header, rcode, qtype, responses; pointer-loop safe; non-ASCII bytes kept as visible escapes.
- Decoder: DNS info on queries and responses, port quoted in ICMP unreachables, ICMP payload length, IP protocol number, fragment offset and More-Fragments flag.
- `netguard rules` (text/JSON) with per-rule state from the configuration; rule metadata on every detector.
- Configurable `max_keys` for the window detectors; ratios and probabilities validated (≤ 1, TRW ordering).
- 13 new lab scenarios (7 attacks, 6 benign look-alikes); scenario-level detection line in the scorecard.
- ADR-0006, ADR-0007, learning notes 03 and 04 (Turkish), 8 rule pages.

### Changed
- NG-SCAN-001 is outcome-aware: incidents in which more than `max_open_ratio` (0.8) of the ports were open are not reported. Fixes the `passive_ftp` false positive.
- The engine dispatches `on_packet` by protocol (`Detector.packet_protos`) and only calls hooks a detector implements.
- `Packet.dns_query` is now a property over the new `Packet.dns` field.
- Lab scenario `benign_office`: its 40 HTTPS connections now complete (they used to be SYNs without any answer, which no real browsing produces).

### Measured
- Synthetic scorecard: 13/13 attack scenarios detected, 8/11 benign scenarios quiet; entity-level precision 0.83, recall 0.94.
- Reference benchmark with 11 rules: ~2.45 s (v0.2.0 with 3 rules: 2.2 s). Worst-case flood: 469 MB peak.

## [0.2.0] - 2026-10-22

Phase 2 (flow and feature extraction) plus Phase 1 hardening.

### Added
- Flow engine (`flows.py`): bidirectional flows with originator detection, per-direction packet/byte/payload counters, Zeek-compatible `conn_state` and `history`, retransmission and sequence-gap counting (RFC 1982 serial arithmetic), state-dependent idle timeouts with O(1) expiry, port-reuse handling and LRU eviction at `max_flows` (ADR-0004).
- `netguard flows -f csv|jsonl` flow export; `[flows]` configuration section.
- Detector hook `on_flow_end(flow)`; engine `on_flow` callback.
- Statistics: packet-size histogram, adaptive time series, flow states, top services, top flows, endpoint table with sent/received bytes (bounded, flagged `approximate` when pruned), fragment and unsupported-link-type counters.
- Alert model v1: stable `rule_id` (`NG-SCAN-001`, `NG-SWEEP-001`, `NG-ARP-001`), deterministic `alert_id`, `schema_version` "1.0"; contract test; rule catalog in `docs/rules/`.
- Own pcap/pcapng readers (`formats.py`): multi-interface pcapng with per-interface link type and timestamp resolution, bounded length fields, truncated-capture reporting, `capture` section in JSON output (ADR-0005).
- Decoder: TCP sequence/ack numbers, payload length from the IP header (correct under short snaplen), TTL/hop limit, IPv4 fragment flag; non-first fragments decode as `ip-frag`.
- `struct`-based decode fast path with a differential fuzz test against dpkt.
- Reproducible benchmarks: `benchmarks/make_bench_pcap.py`, `benchmarks/flood_memory.py`.
- ADR-0004, ADR-0005, learning note 02 (Turkish).

### Changed
- Reference benchmark: ~2.2 s instead of 3.4–3.9 s for 242 003 frames (M1), despite the added flow tracking.
- "Top talkers" now rank by bytes sent + received (previously sent only).
- Frames with an unsupported link type are counted and skipped instead of aborting the analysis.
- A closed incident clears its key's window: the next incident can no longer re-use already-reported events. Effect: periodic sweeps (e.g. `monitoring_poller`) produce one alert per burst with correct duration instead of overlapping alerts. Entity-level scorecard unchanged.
- Roadmap restructured into phases 0–10; MVP redefined as v0.5.0 (dashboard included).

### Fixed
- **Detection bypass:** a DNS query name with invalid UTF-8 made the whole UDP/53 packet a decode error, hiding it from every detector.
- **CPU exhaustion:** a full detector key table re-scanned every window for each new source (O(max_keys) per packet under a spoofed-source flood); expiry also scanned every window on each tick. Both are now amortized O(1) with LRU ordering.
- **Memory exhaustion:** the per-IP byte counter grew without bound. Per-key detector state shrank from 1 996 to 668 bytes, measured with tracemalloc (list-based windows, lazily created pending incidents). Worst-case flood (500k spoofed sources): 349 MB peak, 8.7 s; before these fixes the same run did not finish within 120 s.
- **Unbounded read:** a pcap record with `caplen = 0xFFFFFFFF` made the reader buffer up to 4 GiB of a stream into one frame.
- Multi-interface pcapng captures decoded every interface with the first interface's link type.

## [0.1.0] - 2026-10-20

### Added
- pcap/pcapng reader for files and non-seekable streams (`tcpdump -w - | netguard analyze -`).
- Hardened decoder for Ethernet, Linux SLL, BSD loopback, raw IP; IPv4/IPv6; TCP, UDP, ICMP, ICMPv6, ARP; DNS query names.
- Sliding-window distinct counter and incident aggregation (`window.py`).
- Detectors: `portscan` (SYN/NULL/FIN/XMAS, open/closed port evidence), `hostsweep` (ICMP/ARP/TCP, alive hosts), `arpspoof` (binding changes with suspect attribution and escalation).
- MITRE ATT&CK mapping, text/JSON/JSONL output, TOML configuration with allowlist.
- Lab: 11 labelled synthetic scenarios, `netguard lab generate|list|evaluate`, scorecard locked by tests.
- CI (ruff, mypy --strict, pytest on Linux/macOS × Python 3.11–3.13).
