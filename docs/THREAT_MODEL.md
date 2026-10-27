# Threat model

NetGuard reads attacker-controlled bytes by design (packets, capture files,
DNS names) and, when serving, exposes an HTTP API and a dashboard. This page
lists what is protected, from whom, at every entry point, and which test pins
each defence. Reviewed for v0.8.0 (Phase 9); updated after the external audit of 27 October 2026.

## Assets and adversaries

| Asset | Why it matters |
|---|---|
| Stored captures and results | Contain other people's traffic: credentials, personal data |
| Detection integrity | An attacker who can hide traffic or disable rules escapes detection |
| Availability of the analyzer | A crashed or stalled IDS sees nothing |
| The host | NetGuard must not become a way into the machine it runs on |

| Adversary | Capability |
|---|---|
| Network attacker | Chooses the bytes on the wire NetGuard analyses |
| Malicious capture author | Hands a crafted pcap to an analyst who uploads it |
| Malicious web page | Runs in the analyst's browser while the API listens on localhost |
| Network client of the API | Reaches the port when it is exposed beyond loopback |

## Entry points

| Entry point | Threats | Mitigations | Pinned by |
|---|---|---|---|
| Capture file / stream | Huge length fields, truncation, malformed blocks | Own readers with 16 MiB record cap, truncation reported, structural errors raised (ADR-0005) | `test_formats.py` |
| Packet decoding | Crash or exception hides a packet (detection bypass); parser differential | Never raises; struct fast path checked against dpkt by a differential fuzz test; malformed DNS loses only its fields | `test_decode.py`, `test_dns.py` |
| Detector state | Spoofed-source floods exhaust memory or CPU | Every table bounded, eviction O(1), drops counted (fail-open) | `test_window.py`, `test_flows.py`, `benchmarks/flood_memory.py` |
| Evasion | Slow scans, fragmentation, rogue DHCP laundering ARP spoofing | TRW without window, fragment rule, trusted-server DHCP correlation | `test_scenarios.py`, `test_phase7.py` |
| Live capture | Privileged code parsing traffic; argument injection; symlink overwrite with `--write`; memory growth in sessions that run for days | NetGuard refuses root, alert history bounded to the latest 10 000 events (every event is still printed, drops are counted), time series bounded, tcpdump holds capture privilege (`-Z` with sudo); argv without shell, validated interface; output opened `O_EXCL|O_NOFOLLOW` before tcpdump starts | `test_live.py` |
| Upload | Disk exhaustion (also by concurrent uploads), non-capture files, path traversal via filename | Streamed with size cap; global storage quota with per-chunk reservations shared by concurrent uploads and released on failure or disconnect; magic check, random stored names, SHA-256 de-duplication | `test_api.py`, `test_guard.py` |
| Analysis jobs | Parser bug or memory bomb takes the API down; job flood | Separate worker process with timeout, `RLIMIT_CPU`, `RLIMIT_AS` (Linux), queue limit | `test_store_jobs.py`, `test_api.py`, Linux container check |
| API queries | SQL injection, huge pages | Bound parameters, allowlisted sort keys, page ≤ 1000 | `test_api.py` |
| Malicious web page (localhost API) | **DNS rebinding** (reads all data), **cross-site writes** via "simple requests" (also from another port on the same host), large bodies | Host allowlist (421), unsafe methods refused (403) unless `Origin` is absent or equals the server's scheme, host and port or an explicitly allowed origin (`null` and malformed origins refused), raw-body endpoints require non-simple content types (415), 1 MiB body cap outside the upload | `test_guard.py` |
| Remote API clients | Unauthenticated access | Loopback by default; non-loopback refused without a ≥ 16-char bearer token (constant-time compare) | `test_api.py` |
| Dashboard | Stored XSS from capture strings, clickjacking | Text-only rendering, CSP `script-src 'self'`, `frame-ancestors 'none'`, no inline scripts (CI check) | `security.test.tsx`, CI frontend job |
| HTML report | XSS from capture strings | Everything escaped, CSP without scripts | `test_report.py` |
| Stored data at rest | Other local users read captures | Data directory 0700, files 0600, process umask 077 (also for SQLite WAL files); warning if the directory is shared | `test_api.py`, Linux container check |
| Dependencies | Known vulnerabilities, license conflicts | pip-audit and pnpm audit in CI (weekly too), license gate, CycloneDX SBOM per release | CI `security` and `frontend` jobs |

## Findings fixed in Phase 9

1. **DNS rebinding** (high): with the default localhost/no-token setup, a page
   whose domain re-resolved to 127.0.0.1 could read every capture and alert.
   Now refused by the Host allowlist.
2. **Cross-site writes** (medium): a page could upload captures and import a
   profile disabling a rule with `text/plain` requests (no CORS preflight).
   Now refused (Origin check and content types).
3. **Unbounded JSON bodies** (low): read fully before validation. Now capped.
4. **Disk and queue exhaustion** (medium, authenticated): no global storage
   quota or queue limit. Now `--max-storage-gb` (507/413) and 100 pending
   analyses (429).
5. **`--write` followed symlinks and truncated existing files** (medium on
   shared hosts). Now created exclusively, without following links.
6. **SQLite WAL/SHM files inherited the default umask** (low): now 077.
7. **Broken-pipe exit code 120** on Python 3.14 (robustness).

## Findings fixed after the external audit (27 October 2026)

An independent review reproduced four defects that the Phase 9 tests did not
cover. Each now has a regression test that failed before the fix.

1. **Concurrent uploads exceeded the quota** (medium): the free space was
   checked once per upload, so two 400-byte uploads against a 500-byte quota
   both succeeded (800 bytes stored). Fixed with reservations
   (`test_concurrent_uploads_cannot_exceed_the_quota`).
2. **Origin compared host names only** (medium): `http://localhost:9999` was
   accepted for writes to `http://localhost`, including a body-less POST that
   starts an analysis. Exploiting it needs a malicious page served from
   another port of the same host; not demonstrated with a real browser.
   Fixed: scheme, host and port must match (`test_origin_must_match_scheme_host_and_port`).
3. **Unbounded alert history in live sessions** (low, availability): every
   alert event stayed in memory for the whole session. Fixed with a bounded
   history (accelerated 25-hour capture-clock test; not a 25-hour wall-clock run).
4. **Time series could exceed its bucket limit** with sparse timestamps (low).

## Residual risks (accepted, documented)

- No TLS in NetGuard itself: put a reverse proxy in front (deploy/Caddyfile).
- macOS does not enforce the worker memory limit (timeout and CPU limit apply).
- Single shared token, no users or roles: fits a single analyst or a small lab.
- A rogue DHCP server answering before the real one becomes trusted (TOFU):
  configure `dhcp_servers`.
- No IP fragment reassembly; IPv6 fragments and DHCPv6 not inspected.
- Capture permission for tcpdump (setcap) applies to every user who can run it.
