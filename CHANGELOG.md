# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning: [SemVer](https://semver.org/).

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
