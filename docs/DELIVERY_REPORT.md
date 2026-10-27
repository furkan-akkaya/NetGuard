# Delivery report: NetGuard 1.0.0rc1 (release candidate)

State on 27 October 2026, branch `fix/audit-2026-10-27` (pull request #9,
which contains #8). Nothing is tagged, released or public. This page says what
the candidate contains, what backs each claim, and what is still open. It
claims nothing that was not run.

## Verdict

**A release candidate, not v1.0.0.** 8 of the 12 Definition-of-Done items
are met; 4 are partly met and need the lab or a release run
([RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md)). Tagging `v1.0.0rc1` would
create a private draft pre-release from exactly this source.

## What it is

A passive network intrusion-detection tool for home and lab networks: reads
pcap/pcapng or a live interface (through tcpdump), rebuilds flows with
Zeek-compatible states, runs 11 explainable detection rules with confidence
scores and correlation, and serves results through a CLI, a REST API and a
web dashboard. One Python package (`netguard`, Python ≥ 3.11); the analyser
needs only `dpkt`, the web extra adds FastAPI and Uvicorn.

| Topic | Where |
|---|---|
| Install, verify artefacts, live-capture permissions, upgrade, uninstall | [DEPLOYMENT.md](DEPLOYMENT.md) |
| Usage (CLI, API, dashboard) | [README.md](../README.md), [API.md](API.md), [DEMO.md](DEMO.md), [LIVE_CAPTURE.md](LIVE_CAPTURE.md) |
| Rules and limits | [rules/](rules/), [EVALUATION.md § 5](EVALUATION.md) |
| Security | [THREAT_MODEL.md](THREAT_MODEL.md) |
| Release notes | [CHANGELOG.md](../CHANGELOG.md) `[1.0.0rc1]` (the release workflow publishes this section) |

## Evidence

Checked on this branch before the final commit (CI re-runs all of it on the
head commit; its result is recorded on the pull request, not here, because a
commit cannot contain its own CI result):

| Check | Result |
|---|---|
| Python tests (macOS, Python 3.11) | 397 passed, coverage 93.25 % (gate 90 %) |
| Lint, format, strict types | ruff clean, mypy `--strict` clean (76 source files) |
| Dashboard | 14 tests passed, production build OK |
| Dependencies | pip-audit and pnpm audit: no known vulnerabilities; license gate (no GPL/AGPL/SSPL/EUPL) passed |
| Version fields | `1.0.0rc1` in pyproject, package and dashboard (`release_checks.py versions`) |
| CI matrix | Linux and macOS × Python 3.11-3.14, lint, frontend, security |
| Release artefacts | built by `release-dryrun.yml` on every pull-request push, without a tag: wheel, sdist, locked requirements, CycloneDX SBOM, `SHA256SUMS` |

Real traffic (isolated UTM lab, details in [EVALUATION.md § 6](EVALUATION.md)):

| Capture | Result |
|---|---|
| exp01, nmap SYN scan, offline | NG-SCAN-001 and NG-SCAN-002 with the declared entities, 0 false positives; flows equal to Zeek 8.2.2 (1001/1001) |
| live-syn-01, same scan, live | live final alerts equal offline analysis except `reported_at`; 0 kernel drops; Zeek 1000/1000 |
| benign-01, 1 h low-rate SSH/ping traffic, live | 0 alerts live and offline, 0 kernel drops, peak RSS 34.0 MiB; flows equal to Zeek with its DNS timeout at 60 s |

All three are pinned by `eval/lab/real_regression.py --zeek` (packets,
flows, flow states, final alerts, Zeek equality); it passed on this branch.
The live runs used a build of commit `a845dea`; they were not repeated with
later builds.

## Not verified, or not met

- Precision/recall on real traffic: one attack type so far. Nine further
  scans, a bounded SYN burst, ARP, DNS and baseline experiments are prepared
  but not run ([eval/lab/RUN.md](../eval/lab/RUN.md)).
- Live early-warning delay: not measured (runner ready: `live-early-01`).
- False-positive rate on real networks: the benign hour is one narrow traffic
  mix, not a rate.
- Long runs (more than 1 h), high traffic on a live interface.
- The tag-triggered release workflow (draft creation) has never run.
- systemd unit on a real host (`systemd-analyze` only).

## Remaining steps for the owner

1. Run the lab kit ([eval/lab/RUN.md](../eval/lab/RUN.md)) and transfer the
   results; the analysis on the Mac is scripted.
2. Review and merge pull request #8, then #9.
3. Decide on the tag `v1.0.0rc1` (private draft pre-release) and, after the
   lab results, on `v1.0.0` and on repository visibility.
