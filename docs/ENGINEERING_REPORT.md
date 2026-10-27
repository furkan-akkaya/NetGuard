# Engineering evaluation report

What NetGuard is, how it was built, what was verified and how, and what was
not. Every number here comes from a measurement documented in
[EVALUATION.md](EVALUATION.md) (with the command that reproduces it) or from
the repository itself. State: v0.8.0 plus the Phase 10 changes, October 2026.

## 1. Summary

NetGuard is a network intrusion detection and traffic analysis tool for
capture files and live traffic on small networks. It reads pcap/pcapng
(or a `tcpdump` stream), rebuilds bidirectional flows, runs 11 explainable
detection rules, and reports alerts with evidence, a confidence score and
ATT&CK mapping, through a CLI, an HTML report, a REST API and a web dashboard.

It is deliberately **not** a replacement for Zeek or Suricata: no signature
language, no application-layer protocol analysers beyond DNS and DHCP, and
about 100k packets/s offline on one core. Its value is a small, readable,
measured codebase where every alert can be traced to the packets and
thresholds behind it.

| Area | Size |
|---|---|
| Python package (`src/netguard`) | ~8 800 lines, 45 modules |
| Python tests | ~3 100 lines, 325 tests, 93% branch-aware coverage (CI gate: 90%) |
| Dashboard (`frontend/src`, React + TypeScript) | ~2 300 lines, 14 tests |
| Documentation | 11 ADRs, 11 rule pages, 9 guides plus this report, 10 learning notes (Turkish) |
| Runtime dependencies | analyzer: dpkt; API extra: FastAPI, Uvicorn |

## 2. Architecture in one paragraph

Bounded capture readers → a decoder with a `struct` fast path (checked
against dpkt) → a flow table with Zeek-style connection states → detectors
that see packets, TCP handshake events and finished flows, all on the
capture clock → alerts aggregated into incidents (early and final stage) →
confidence scoring and correlation → output (text, JSON, ECS, HTML, SQLite).
The API stores captures and results in SQLite and runs every analysis in a
separate worker process with time and memory limits. Live capture delegates
privileges to `tcpdump`; NetGuard itself refuses to run as root. Details:
[ARCHITECTURE.md](ARCHITECTURE.md).

## 3. Key decisions

| Decision | Why | Record |
|---|---|---|
| Python, dpkt as fallback decoder | Readability and testability for a portfolio project; speed is measured and managed | ADR-0001 |
| Own pcap/pcapng readers and fast decoder | dpkt trusted `caplen`: one hostile record header turned a 300 MB stream into one packet and 628 MB peak RSS; the own reader rejects it at 31 MB. The fast path also recovered the performance budget | ADR-0005 |
| Incidents instead of per-packet alerts | A 65 535-port scan should be one alert with evidence, not 65 535 | ADR-0003 |
| Outcome-aware scan detection (TRW) | A window rule misses slow scans; a sequential test on connection outcomes does not need a window | ADR-0006 |
| Per-host EWMA baselines | "Unusual" depends on the host; clipping keeps an attack from teaching the baseline | ADR-0007 |
| SQLite and worker processes | No database server to run; a parser bug or memory bomb kills one job, not the API | ADR-0008 |
| Early and final alert stages | Live alerts within seconds without giving up incident aggregation | ADR-0010 |
| Phase 7 scope | Built confidence, correlation, DHCP correlation, profiles; deferred or rejected features with no data to measure them (ML, Zeek/Suricata input) | ADR-0011 |

## 4. Defects found by measuring, not by reading

The most useful results of the project were defects that only showed up when
something was measured or attacked:

| Found by | Defect | Fix |
|---|---|---|
| Hostile capture on a pipe | Unbounded allocation from an untrusted length field in dpkt's reader | Own bounded readers (16 MiB record cap) |
| Spoofed-source flood benchmark | O(n) cleanup when a detector table was full: 500k packets did not finish in 120 s | O(1) LRU eviction; per-key memory 1 996 → 668 bytes |
| Throughput budget (≤ 20% regression per phase) | The first flow-table version was 28% slower | `struct` fast path, protocol dispatch |
| Differential fuzzing (fast path vs dpkt) | A quoted inner IP header shorter than its own header length | Fast path declines such frames |
| Intermittent test failure | A finished job's worker could be killed as "cancelled" (race) | Finished workers are allowed to exit |
| Attacking the localhost API from a browser (Phase 9) | DNS rebinding could read all data; `text/plain` requests could upload captures and disable rules | Host allowlist, Origin check, non-simple content types |
| Clean install on Python 3.14 (container) | Broken pipe exited with code 120 | Flush inside the handler; 3.14 added to CI |
| Screenshots of real analyses (Phase 10) | The traffic chart interpolated across empty time buckets, drawing a ramp where there was a gap | Step chart that drops to zero |
| Code review against the threat model (Phase 10) | Detector state dropped under a flood was counted but never shown, although the docs said it was | Counters in the output, warnings in CLI, report and dashboard |
| Dependency review (Phase 10) | `python-multipart` was installed with the API but never used (uploads are raw streamed bodies) | Removed: one dependency less to patch |
| External audit (27 Oct 2026), concurrency test | Two concurrent uploads both passed the quota check (800 bytes stored under a 500-byte quota) | Per-chunk quota reservations |
| External audit, HTTP-level test | Origin check ignored the port: another local port could change data | Scheme, host and port compared; `--allowed-origin` for proxies |
| External audit, accelerated 25 h capture clock | Live sessions kept every alert event in memory | Bounded history; every event still streamed, drops counted |
| External audit, sparse timestamps | Time series held more buckets than its limit | Downsample until the limit holds |
| External audit, clean install vs lock | The tested wheel ran Starlette 1.10.0 while lock and SBOM said 1.9.0 | Release installs with the lock as constraints and verifies the installed set |

## 5. Verification

### Automated (every push, GitHub Actions)

- Lint (ruff), types (mypy `--strict`), 325 tests on Ubuntu and macOS ×
  Python 3.11–3.14, coverage ≥ 90%.
- 27 labelled scenarios (15 attack, 12 benign look-alikes) whose true/false
  positives are pinned by `tests/test_scenarios.py`.
- Differential fuzzing of the decoder (5 000 mutants per run).
- Dashboard: type check, 14 tests, production build, a check that the
  bundle has no inline scripts (CSP).
- Dependency audit (pip-audit, pnpm audit) and a copyleft license gate, also
  weekly.

### Measured (reproducible, [EVALUATION.md](EVALUATION.md))

| Measure | Result | Scope |
|---|---|---|
| Synthetic scenarios, entity level | precision 0.87, recall 0.95 (TP 20, FP 3, FN 1); 15/15 attack scenarios detected; 9/12 benign scenarios quiet | Synthetic traffic designed by the same author as the rules |
| False positives vs true positives, confidence | FPs 25–30, TPs 45–95 | Consistency check, not accuracy |
| Detection delay (live pipeline, early warnings) | 0–2 s for fast scans, sweeps, ARP spoofing and fragments; 76 s for a slow scan (TRW; the window rule misses it); 11–20 s for SYN flood and DNS rules; ~60 s for baseline rules | Synthetic scenarios replayed through the live engine |
| Offline throughput | 2.47 s for 242 003 frames (~98k packets/s), 34 MB RSS | Apple M1, Python 3.11, one process |
| Spoofed-source flood, 500k packets | 469 MB peak RSS, bounded; the flood is detected, other rules drop state (now reported) | Worst case for state exhaustion |
| Decoder fuzzing campaign | 250 000 mutants, 0 exceptions, 0 fast-path mismatches (v0.3.0) | One-off, per release |

### Verified by hand

- Clean wheel installation on macOS and in an Ubuntu 26.04 ARM64 container:
  analysis, server, dashboard, uploads.
- The worker memory limit enforced on Linux (a 40 MB limit stopped a large
  analysis cleanly; the server kept running).
- Live capture on loopback in the container as an unprivileged user with
  `setcap`: early warnings 1 s after the scan began; live and offline
  results identical.
- The dashboard in a browser against real analyses (Phase 5 and Phase 10),
  including the security checks (CSP, text-only rendering of capture data).

## 6. Not verified

These are stated here so that nothing above is read as covering them:

| Item | Why not yet | Who |
|---|---|---|
| Real-network detection quality (Phase 8) | Three real lab captures so far (two SYN scans, one hour of low-rate benign traffic; EVALUATION.md § 6): too few attack types for precision/recall, and the benign hour is not a false-positive rate for real networks | User captures, then re-evaluation |
| Live capture on a real interface | Two runs on the lab VM's interface (90 s scan, 1 h benign) with a build of `a845dea`: 0 kernel drops, live = offline final alerts. Not under load, not longer than 1 h | User |
| systemd unit on a real host | `systemd-analyze` passes (exposure 1.6); never run under systemd | User's Ubuntu server |
| Release workflow | Its gates ran without a tag in `release-dryrun.yml`; the tag-triggered workflow itself has not run (no tag pushed) | Release step (10.5) |
| Browsers other than Chrome | Dashboard checked in Chrome only | Open |
| Long-running live sessions (days) | Memory is bounded by design and by test; the longest live run is 1 h of low-rate traffic (peak 34.0 MiB RSS); not soak-tested | Open |

## 7. Limitations

Detection and operational limitations, each with its status, are listed in
[EVALUATION.md §5](EVALUATION.md#5-known-limitations-reviewed-in-phase-10) and
the residual security risks in [THREAT_MODEL.md](THREAT_MODEL.md). The most
important for a reader of the results:

- Accuracy numbers are for synthetic scenarios only.
- No fragment reassembly, no encrypted-DNS visibility, no application-layer
  analysis beyond DNS and DHCP.
- Not a line-rate sensor.
- A spoofed-source flood can hide other activity; NetGuard now says when this
  happened, but cannot prevent it with bounded memory.

## 8. Lessons

1. **Untrusted input includes length fields inside trusted libraries.** The
   largest memory problem came from a library reading a capture, not from
   NetGuard's own code.
2. **Bounded is not enough; the cost of hitting the bound matters.** A full
   table that is cleaned in O(n) is a CPU-exhaustion attack.
3. **"Counted" must mean "shown".** A counter nobody can see is not
   observability; the Phase 10 review found exactly this.
4. **Benign look-alikes are as important as attacks.** Each rule was designed
   against the traffic it must *not* flag, and three known false positives are
   published instead of tuned away.
5. **localhost is not a security boundary.** The browser is a client that
   runs attacker code inside the machine.
6. **Measure before claiming.** Every performance and detection number in the
   documentation has a command next to it; where nothing was measured, the
   documentation says so.
