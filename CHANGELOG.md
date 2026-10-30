# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning: [SemVer](https://semver.org/).

## [Unreleased]

## [1.0.0rc2] - 2026-10-30

Release candidate; stable 1.0 criteria remain incomplete.

### Fixed
- Baseline rules now learn and score only fully observed epoch-aligned intervals. Discard partial first and EOF intervals; preserve final alerts from completed intervals. No threshold changes.
- Add regression coverage for start offsets, exact boundaries, warm-up, silence, clipped learning, EOF and both rate/volume rules.

### Documentation and validation
- Include the plain-language bilingual README from PR #10; #8 and #9 are already merged.
- Record the baseline decision and its edge blind spots in docs/BASELINE_INTERVALS.md.
- Recheck 17 existing real captures, including Zeek comparisons with documented timeout/fragment limits; synthetic scorecard stays TP=20, FP=3, FN=1.
- Review confidence factors without fitting weights to reused lab data. Scores are not calibrated attack probabilities.
- Prepare a bounded stepped-load helper and analyser CPU sampling. New >1-hour live and repeated load runs remain unexecuted without guest sudo/control access.

Install verified release assets with `pip install -c netguard-1.0.0rc2-requirements.txt "netguard-1.0.0rc2-py3-none-any.whl[web]"`.
See docs/PUBLICATION_RC2.md for checks, limits and upgrade/rollback instructions.

## [1.0.0rc1] - 2026-10-27

Release **candidate**, not v1.0.0: the Definition of Done is not fully met
(docs/RELEASE_CHECKLIST.md). It collects Phase 10 (code-quality review,
evaluation report, release preparation), the fixes from the external audit
of 27 October 2026 and the first real lab measurements. Every number below
comes from a run that was performed; what was not measured is said so.

Install: verify `SHA256SUMS`, then
`pip install -c netguard-1.0.0rc1-requirements.txt "netguard-1.0.0rc1-py3-none-any.whl[web]"`
(docs/DEPLOYMENT.md, which also covers live capture permissions, upgrading
and uninstalling). Known limits: docs/EVALUATION.md § 5 and § 6.

### Added
- Analysis statistics report every detector's counters (`stats.detectors`). When a detector dropped state because its table was full (`evicted_*`, `untracked_*`), the text output, the HTML report and the dashboard show a warning. Before, these losses were counted internally but never shown, although the docs said they were.
- NG-ARP-001 counts new IPs it could not track because the binding table was full (`untracked_ips`).

### Measured (first real lab capture, 27 Oct 2026)
- One real nmap SYN scan (isolated UTM lab, hash-verified capture): NG-SCAN-001 and NG-SCAN-002 fired with the declared entities, 0 false positives (4 stray SSDP multicast packets raised nothing). Flow states matched a real Zeek 8.2.2 `conn.log` exactly (1001/1001, zero differences). Replay through the live pipeline produced the same final alerts as offline analysis.
- The same scan captured live by `netguard monitor` on the victim (live-syn-01, 90 s, 0 kernel drops reported): the two live final alerts equal offline analysis of the written pcap in every field except `reported_at`, and flow states match Zeek 8.2.2 (1000/1000). Two captures of one attack type are not precision/recall for the tool, and live delay with early warnings is not measured. See docs/EVALUATION.md § 6.
- One hour of live benign lab traffic (benign-01: paced SSH banner reads and pings from Kali, multicast background; build of `a845dea`): 4245 packets, 0 kernel drops, 0 final alerts live and offline, analyser peak RSS 34.0 MiB. Flow states matched Zeek 8.2.2 for 396 of 397 flows; the mDNS split comes from Zeek's 10 s DNS session timeout, and one FIN-then-RST connection was RSTO in NetGuard but SF in Zeek (fixed, see below). One narrow traffic mix: not a false-positive rate or a memory guarantee for real networks.

### Security
- Concurrent uploads could exceed the storage quota (two 400-byte uploads against a 500-byte quota were both stored). Uploads now reserve quota per chunk; reservations are released when the capture is stored or the upload fails, is rejected or disconnects.
- The Origin check compared host names only: `http://localhost:9999` could change data on `http://localhost`, including a body-less POST that starts an analysis. Scheme, host and port must now match; `null` and malformed origins are refused. **Behind a TLS proxy, add `--allowed-origin https://<name>`**, or dashboard writes get 403.

### Added
- `netguard lab evaluate --manifest`: score checksum-pinned captures against ground truth declared in advance (tool, tool version, command, provenance, configuration hash); lab, public and synthetic scores are kept apart; integrity failures exit 2 without a score. Adapted from an earlier unmerged patch after review.
- `netguard lab compare-flows`: compare every TCP/UDP flow (endpoints, direction, state) with a Zeek JSON `conn.log`.
- `--allowed-origin` for `netguard serve`.
- Statistics: `alerts.events_total`, `alerts.final_total`, `alerts.history_dropped`.
- docs/CAPTURE_EVALUATION.md; lab acceptance criteria in LAB_SETUP.md, fixed before any lab result.
- `eval/lab/`: lab scripts for the isolated UTM network (victim capture that announces readiness only after tcpdump reports `listening on`, refuses cleanly when sudo, tcpdump or the interface fails, captures in immediate mode and records the hash and tcpdump's counts, experiment 01 SYN scan with address and confirmation guards, `ingest.py` that verifies transferred captures and writes the manifest) and `experiments.toml` with ground truth written before any run.
- LAB_SETUP.md rewritten for the lab as built: one named Host Network, no route to the Mac or internet, transfer-channel requirements, a one-line tool check for the victim, and expected results that match the current rules (UDP scans: NG-SCAN-003; slow scans: NG-SCAN-002).

- `eval/lab/kali-run.sh`: one guarded runner for every planned attack experiment (SYN/connect/XMAS/FIN/NULL/slow/UDP scans, ping sweep, fragmented scan, a bounded SYN burst), each refusing to run outside 10.77.0.10 -> 10.77.0.20 and bounded (fixed ports/counts/rates, no unbounded flooding). `experiments.toml` carries their ground truth, written before any run, listing only the detectors each experiment should trigger on this two-VM topology.
- `eval/lab/victim-live-rss.sh`: runs `netguard monitor --sudo` (NetGuard stays a normal user, tcpdump via `sudo -n`), announces readiness only after a tcpdump capture process is actually running, samples the analyser's RSS and records VmHWM (the kernel's peak), the monotonic elapsed time, the monitor exit status, kernel-drop count and write-truncation, and reports NEEDS REVIEW instead of success on a failed, short, under-sampled or lossy run.
- `eval/lab/kali-benign.sh`: paced, non-scanning client traffic for the benign baseline. `eval/lab/live_offline_equal.py`: compares a live JSONL run's final alerts with offline analysis of the written pcap. `eval/lab/zeek-compare.sh`: runs Zeek on a capture and compares flows.
- `.github/workflows/release-dryrun.yml`: runs every release gate and uploads the artefacts (wheel, sdist, SBOM, checksums, locked requirements) WITHOUT a tag or a release, with a read-only token. It runs on pull requests that touch what a release is built from; the manual `workflow_dispatch` trigger only becomes available once the file is on the default branch (a dispatch from this branch returned HTTP 404).

### Changed
- Live sessions keep the latest 10 000 alert events in memory; every event is still printed, and the summary says when older ones were dropped. Offline analyses keep every alert.
- Release workflow: a version with letters (`1.0.0rc1`) becomes a draft *pre-release*.
- Release workflow: re-checks the tagged source (lint, types, tests with the 90% gate, dependency audit, licenses) and all three version fields; installs the wheel with the locked dependencies, checks the installed set against the lock the SBOM is made from, and ships that requirements file; the sdist now contains tests, docs, benchmarks, deploy files and the dashboard sources, may contain only git-tracked files, and must rebuild the dashboard and pass the tests; the smoke-test server is stopped.

### Fixed
- Flow state of connections without a SYN (NULL, FIN and Xmas probes, mid-stream pickup): NetGuard called all of them `OTH`; Zeek applies its endpoint states and reports `RSTRH` (NULL probe answered by RST), `RSTR` (FIN/Xmas probe answered by RST), `SH` (unanswered FIN probe) and so on. NetGuard now does the same: 17 cases checked against Zeek 8.2.2 (state and history), a regression test reduced from the real lab probes, and the real exp03-exp05 captures now equal Zeek (999 differences each before). No detector uses these labels; no alert changed on any of the eleven pinned real captures.
- Flow state when both endpoints reset: NetGuard reported `RSTO`; Zeek checks the responder first and reports `RSTR`, or `REJ` when neither side sent payload. NetGuard now does the same. Only the state label changes: TRW and the SYN-flood rule use connection events, where such a connection was answered and established, never rejected (pinned by a test). Pre-handshake states (S0, REJ, RSTOS0, SH, SHR, RSTRH, OTH) and the 23 FIN/RST orderings tried were checked against Zeek 8.2.2 one pcap each: all equal.
- Flow state: an RST sent after both sides had sent FIN made a normally closed connection `RSTO`/`RSTR`; Zeek reports `SF`. FIN and RST order now follows Zeek's endpoint rules (ADR-0004), checked against Zeek 8.2.2 for 14 orderings, with a regression test reduced from the real lab connection. On the benign lab capture every NetGuard flow now matches Zeek.
- `monitor --sudo` dropped tcpdump's privileges to `SUDO_USER` before the account NetGuard runs as. Started with `sudo -u lab` from root, that named root and the capture was refused. It now drops to the effective user (`SUDO_USER` only when NetGuard itself is root). Found in the lab-kit rehearsal.
- `eval/lab/victim-live-rss.sh` ended silently when NetGuard failed to start (an empty `grep` under `set -e -o pipefail`); it now always prints its RESULT / NEEDS REVIEW verdict. `kali_rate_burst.py` printed its "NOW" prompt before listening, so an immediate upload could be refused; `kali_arp_binding.py` wrote its record to root's home under `sudo`; `victim_volume_burst.py` sent 48 MB faster than tcpdump could keep up (1576 kernel drops, 11 MB captured, below the 20 MB floor) and is now paced at 4 MB/s. All fixed; all four found in the rehearsal. The expected detections were not changed.
- The time series could exceed its bucket limit with sparse timestamps; downsampling now repeats until the limit holds, keeping the totals.
- The dashboard's traffic chart drew a line across empty time buckets, so a gap followed by a burst looked like a gradual ramp. It is now a step chart that drops to zero where no traffic was seen. Its axis labels no longer grow with the chart's width.

### Lab tooling
- Real lab results for eight more experiments (connect, Xmas, FIN, NULL, UDP scans, ping sweep, fragmented scan, SYN burst): each raised exactly its declared detections and no other alert (docs/EVALUATION.md § 6). The fragmented scan differs from Zeek by the documented no-reassembly limit, pinned by size (`zeek_known_difference`). The captures also contain the lab bridge's HTTP control traffic on TCP 8766 (no alerts).
- Real lab results for the slow scan (exp06), the ARP binding change (exp11), DNS NXDOMAIN (exp12) and tunnel-like names (exp13), each exactly its declared detection, and a live early-warning run (live-early-01): early warnings 0.683 s and 0.757 s after the threshold-crossing packet, final alerts equal offline except `reported_at`. Sixteen real captures pinned. The lab bridge's control traffic uses TCP 8766 and 8767.
- `eval/lab/live_delay.py --pcap` finds each early warning's threshold-crossing packet by replaying the run's capture through the same detectors. Before, it called `reported_at - last_seen` the delay after the triggering packet; that is only the age of the newest evidence (0.011 s in live-early-01) and is now labelled so.
- exp14 r02 accepted: 0 kernel drops, raw capture with default rules gives exactly NG-RATE-001 (10.77.0.10) and NG-VOL-001 (10.77.0.20); Zeek 2331/2331. A pre-declared additional analysis without the lab control ports 8766/8767 (19516 packets removed) gives the same two alerts and is reported separately. Seventeen real captures pinned; each of the eleven rules has a real lab detection.
- exp14 run 01 failed and is not counted: at 4 MiB/s tcpdump (default buffer) dropped 9945 of 59091 packets. `victim-capture.sh` now gives tcpdump a 64 MiB buffer (`NG_CAPTURE_BUFFER_KIB`, 1024-262144 KiB) and marks any kernel drop NEEDS REVIEW; `victim_volume_burst.py` defaults to 1 MiB/s (`--rate`, 0.5-4 MiB/s).
- `eval/lab/real_regression.py` with `real-regression.toml`: re-analyses the real lab captures (kept out of git) and fails when packets, flows, flow states or final alerts differ from the pinned values; `--zeek` also requires the Zeek comparison to be equal.
- Bounded runners for the rules the two-VM lab could not exercise, with ground truth written before any run: an ARP binding change for an unused address (exp11), DNS NXDOMAIN and tunnel-like lookups against a minimal lab-only responder on Kali (exp12, exp13), and 13 minutes of baseline followed by a connection and a volume burst (exp14). `live-early-01` and `eval/lab/live_delay.py` measure the live early-warning delay. Rehearsed in network namespaces; not lab results.
- `scripts/build_lab_kit.py`: builds the offline kit for the VMs (single-file `netguard-lab.pyz` with the locked dpkt, the scripts, `RUN.md`, `BUILD.json` naming the commit, `SHA256SUMS`).

### Documentation
- docs/DEPLOYMENT.md: verifying release artefacts (checksums, locked install, SBOM), live capture with `--sudo` or a removable capability, and uninstalling.
- docs/DELIVERY_REPORT.md: what this candidate contains, the evidence for each claim and the steps that remain.
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
