# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning: [SemVer](https://semver.org/).

## [Unreleased]

Phase 10: code-quality review, evaluation report and release preparation.

### Added
- Analysis statistics report every detector's counters (`stats.detectors`). When a detector dropped state because its table was full (`evicted_*`, `untracked_*`), the text output, the HTML report and the dashboard show a warning. Before, these losses were counted internally but never shown, although the docs said they were.
- NG-ARP-001 counts new IPs it could not track because the binding table was full (`untracked_ips`).

### Security
- Concurrent uploads could exceed the storage quota (two 400-byte uploads against a 500-byte quota were both stored). Uploads now reserve quota per chunk; reservations are released when the capture is stored or the upload fails, is rejected or disconnects.
- The Origin check compared host names only: `http://localhost:9999` could change data on `http://localhost`, including a body-less POST that starts an analysis. Scheme, host and port must now match; `null` and malformed origins are refused. **Behind a TLS proxy, add `--allowed-origin https://<name>`**, or dashboard writes get 403.

### Added
- `netguard lab evaluate --manifest`: score checksum-pinned captures against ground truth declared in advance (tool, tool version, command, provenance, configuration hash); lab, public and synthetic scores are kept apart; integrity failures exit 2 without a score. Adapted from an earlier unmerged patch after review.
- `netguard lab compare-flows`: compare every TCP/UDP flow (endpoints, direction, state) with a Zeek JSON `conn.log`.
- `--allowed-origin` for `netguard serve`.
- Statistics: `alerts.events_total`, `alerts.final_total`, `alerts.history_dropped`.
- docs/CAPTURE_EVALUATION.md; lab acceptance criteria in LAB_SETUP.md, fixed before any lab result.
- `eval/lab/`: lab scripts for the isolated UTM network (victim capture with hashing and tcpdump drop counts, experiment 01 SYN scan with address and confirmation guards, `ingest.py` that verifies transferred captures and writes the manifest) and `experiments.toml` with ground truth written before any run.
- LAB_SETUP.md rewritten for the lab as built: one named Host Network, no route to the Mac or internet, transfer-channel requirements, a one-line tool check for the victim, and expected results that match the current rules (UDP scans: NG-SCAN-003; slow scans: NG-SCAN-002).

### Changed
- Live sessions keep the latest 10 000 alert events in memory; every event is still printed, and the summary says when older ones were dropped. Offline analyses keep every alert.
- Release workflow: a version with letters (`1.0.0rc1`) becomes a draft *pre-release*.
- Release workflow: re-checks the tagged source (lint, types, tests with the 90% gate, dependency audit, licenses) and all three version fields; installs the wheel with the locked dependencies, checks the installed set against the lock the SBOM is made from, and ships that requirements file; the sdist now contains tests, docs, benchmarks, deploy files and the dashboard sources, may contain only git-tracked files, and must rebuild the dashboard and pass the tests; the smoke-test server is stopped.

### Fixed
- The time series could exceed its bucket limit with sparse timestamps; downsampling now repeats until the limit holds, keeping the totals.
- The dashboard's traffic chart drew a line across empty time buckets, so a gap followed by a burst looked like a gradual ramp. It is now a step chart that drops to zero where no traffic was seen. Its axis labels no longer grow with the chart's width.

### Documentation
- docs/ENGINEERING_REPORT.md: what was built, the decisions behind it, the defects found by measuring, what was verified and what was not.
- docs/EVALUATION.md: the limitations table is brought up to date (Phase 6–7 fixes, flood state losses); current throughput and flood measurements.
- Learning note 10 (Turkish): reporting what is counted, honest charts, the Definition of Done and release candidates.
- docs/PORTFOLIO.md: LinkedIn (English and Turkish), CV and interview drafts that use only measured claims.
- docs/RELEASE_CHECKLIST.md: the brief's Definition of Done checked item by item. Verdict: not met yet (real-traffic evaluation, live capture on a real interface and a release run are missing), so no v1.0.0 claim.
- docs/DEMO.md: screenshots and command-line output from real runs on the synthetic lab scenarios, with the steps to reproduce them.

### Removed
- `python-multipart` from the `web` extra: installed but never used (uploads are streamed raw bodies).
- Unused code found in the review: `FlowTable.active()`, `FlowTable.flows_started`, `SessionResult.status_lines`, `Host.tcp_to_ip()` in the lab generator.

## [0.8.0] - 2026-10-22

Phase 9: security hardening and CI/CD, against a written threat model
(docs/THREAT_MODEL.md).

### Security
- DNS rebinding: requests with an unknown `Host` are refused (421); `--allowed-host` adds names (e.g. behind a proxy). Before, a malicious page re-resolving its domain to 127.0.0.1 could read all data of a token-less localhost server.
- Cross-site writes: state-changing requests from another `Origin` are refused (403); uploads require `application/octet-stream` and profile imports `application/toml` (415), types a browser cannot send cross-site without a CORS preflight. Before, a page could upload captures and import a rule-disabling profile with `text/plain` requests.
- Request bodies outside the upload are capped at 1 MiB, counted while reading (chunked requests included).
- Global storage quota `--max-storage-gb` (default 10; 507/413) and at most 100 pending analyses (429).
- `monitor --write` creates its file exclusively and without following symlinks, before tcpdump starts.
- The server sets umask 077 (SQLite WAL/SHM files are owner-only) and warns when the data directory is shared.

### Added
- CI `security` job: pip-audit on the runtime dependency set, a copyleft license gate, weekly schedule; Python 3.14 in the test matrix.
- Release workflow (tags `v*`): builds the dashboard fresh, builds sdist and wheel, smoke-tests the wheel in a clean environment, CycloneDX SBOM and checksums, **draft** GitHub release with the changelog section.
- `deploy/netguard.service` (hardened systemd unit, `systemd-analyze security` 1.6 "OK") and `deploy/Caddyfile` (TLS proxy).
- docs/THREAT_MODEL.md, docs/DEPLOYMENT.md, learning note 09 (Turkish).

### Fixed
- Broken-pipe at interpreter exit returned code 120 (seen on Python 3.14): stdout is flushed inside the error handler.
- A tcpdump binary the process may not execute (file capabilities outside a container's bounding set) is explained instead of reported as a bare OS error.

### Verified
- Clean-environment install on macOS and in an Ubuntu 26.04 ARM64 container (Python 3.14): analysis, server and dashboard, worker memory limit enforced on Linux, live capture on loopback as an unprivileged user with `setcap` (early warnings 1 s after the scan started; live = offline on the saved pcap).

## [0.7.0] - 2026-10-22

Phase 7: advanced detection, chosen by measurable value (ADR-0011).

### Added
- Explainable confidence on every alert (contract 1.2, `confidence`: score 5–95, level, base and the evidence factors that raised or lowered it), with every factor justified in docs/CONFIDENCE.md. On the scenarios all false positives score 25–30 and all true positives 45–95 (a consistency check, not an accuracy claim).
- Alert correlation into incidents by actor and time, with ATT&CK tactics in kill-chain order: in `analyze` text/JSON output, `/api/v1/analyses/{id}/incidents` and the dashboard.
- DHCP lease correlation for NG-ARP-001: a binding change assigned by an ACK from the trusted DHCP server (configured, or the first one seen) is not reported; ACKs from other servers never explain a change. New `dhcp.py` parser; `trust_dhcp`, `dhcp_servers`, `dhcp_window_seconds`.
- Rule profiles as TOML: `/profiles/{id}/export.toml`, `/profiles/import`, dashboard export/import; `netguard config` prints the effective configuration as TOML.
- Scenarios: `compromised_workstation` (multi-stage), `dhcp_reassignment_seen` (benign), `arp_spoof_with_rogue_dhcp` (attack).
- Dashboard: confidence column and breakdown, incidents panel.
- ADR-0011, docs/CONFIDENCE.md, learning note 08 (Turkish).

### Deferred
- Zeek/Suricata input, ICMP tunnel rule, resolver policy, seasonal baselines; machine learning rejected until labelled real data exists.

## [0.6.0] - 2026-10-22

Phase 6: live capture and replay.

### Added
- `netguard monitor -i IFACE`: live analysis via a `tcpdump` child process (argument vector, validated interface, BPF filter as one argument), `--duration`/`--count`, `--write` with a size limit (mode 0600), `--sudo` (`sudo -n … -Z $USER`), status lines, clean Ctrl-C shutdown, and a summary with tcpdump's kernel drop statistics. NetGuard refuses to run as root; permission errors explain the platform-specific fix (ADR-0010, docs/LIVE_CAPTURE.md).
- `netguard replay CAPTURE --speed N`: recorded traffic through the live pipeline; its final alerts equal `netguard analyze` (tested).
- Alert lifecycle, contract 1.1: `stage` (`early` when an incident crosses its threshold, `final` when it closes; same `alert_id`) and `reported_at` (capture-clock emission time). `[alerts] early_warning` (on for monitor/replay) and `max_incident_age_seconds`. All rule families support early warnings.
- `Engine.advance()`: the capture clock moves during silence, so live incidents close without a following packet.
- `benchmarks/detection_delay.py` and EVALUATION § Detection delay (time to first alert per attack scenario).
- Dashboard: early-stage badge and detection delay on alerts; ECS export maps `reported_at` to `event.created` and adds `netguard.stage`.
- ADR-0010, learning note 07 (Turkish).

## [0.5.0] - 2026-10-22

Phase 5: the web dashboard. With it NetGuard reaches its MVP: upload a capture,
analyse it, inspect statistics, flows and evidence-backed alerts in the
browser, and export reports and events.

### Added
- Web dashboard (React 19, TypeScript strict, Vite) served by `netguard serve` at `/` (ADR-0009): security overview, captures with upload progress and live job status, analysis view with traffic time series, protocol/state/service/packet-size breakdowns, endpoints, largest flows and a filterable flow browser, alert feed with URL-persisted filters, alert detail with structured evidence and related flows, rule list and profile editor, settings with API token handling.
- Rule profiles: named, validated configuration overrides (`/api/v1/profiles`, schema migration 2); analyses can use a profile plus extra overrides; re-analysis from the dashboard.
- `/api/v1/summary`, flows CSV export, single-file HTML report (`/analyses/{id}/report.html` and `netguard analyze -f html`): no scripts, CSP, every capture string escaped.
- Content-Security-Policy on the dashboard (`script-src 'self'`, `frame-ancestors 'none'`, …); root bundle files served only from inside the bundle directory.
- Frontend tests (Vitest, Testing Library) including hostile-string rendering; CI job: type check, tests, build, no-inline-script check, `pnpm audit`.
- ADR-0009, learning note 06 (Turkish).

### Changed
- The `web` extra is part of the development group, so `uv sync`/`uv run` keep it installed; CI checks the core with `--no-dev`.

### Fixed
- Job runner race: a worker that had stored its result (`done`) but not yet exited could be seen as "no longer running", treated as cancelled and killed; on macOS this raised `PermissionError` from `killpg`. This was the intermittent test failure noted during v0.4.0 development (reproducible on Python 3.12/3.13). A `done` job's worker is now allowed to exit.
- Found in the browser: bar charts collapsed to dots (table column width); the profile-name `pattern` attribute was invalid under the browser's `v`-flag regex syntax, which silently disabled client-side validation (server-side validation was unaffected).

## [0.4.0] - 2026-10-22

Phase 4 (backend, persistence and API). The analyzer core is unchanged and
still has a single runtime dependency; the API ships as the `web` extra.

### Added
- `netguard serve`: REST API v1 (FastAPI) with OpenAPI docs at `/api/v1/docs` (ADR-0008, docs/API.md).
- SQLite store (WAL, versioned migrations): captures, analyses with configuration snapshots, alerts, flows; filtered, sorted and paginated search with allowlisted sort keys.
- Job runner: queued analyses run one at a time in `python -m netguard.worker` processes with a wall-clock timeout, CPU limit and (Linux) memory limit; cancellation kills the worker; interrupted jobs are re-queued once after a restart; partial results of failed jobs are removed.
- Uploads as streamed raw bodies with a hard size cap, pcap/pcapng magic check and SHA-256 de-duplication; client filenames are display-only.
- Alert export as NDJSON in the native format or Elastic Common Schema (`events.py`).
- Configuration from JSON (`config_from_mapping`, `merge_config`) for per-analysis overrides.
- Secure defaults: loopback bind, bearer token required for remote access (constant-time comparison), security headers, data directory `0700` and files `0600`.
- docs/API.md, ADR-0008, learning note 05 (Turkish); SECURITY.md section on running the API.

### Changed
- CI installs the `web` extra, fails if it is missing (instead of silently skipping API tests), and checks that the core still works without it.
- Coverage also measures the worker subprocesses.

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
