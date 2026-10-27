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
| Python tests (macOS, Python 3.11) | 425 passed, coverage 93.27 % (gate 90 %) |
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
| exp02-exp05, exp07-exp10 (connect, Xmas, FIN, NULL, UDP scans, ping sweep, fragmented scan, SYN burst), offline | each raised exactly its declared detections, no other alert, 0 kernel drops; flows equal to Zeek except exp09 (no fragment reassembly, a documented limit); NULL/FIN/Xmas found a flow-state bug, fixed |
| exp06 slow scan (`-T1`), exp11 ARP binding change, exp12 DNS NXDOMAIN, exp13 DNS tunnel-like names, offline | each exactly its declared detection (NG-SCAN-002, NG-ARP-001, NG-DNS-002, NG-DNS-001), no other alert, 0 kernel drops; flows equal to Zeek (exp13 with Zeek's attempt timeout set to NetGuard's 30 s) |
| live-early-01, SYN scan, live with early warnings | early warnings 0.683 s (NG-SCAN-001) and 0.757 s (NG-SCAN-002) after the threshold-crossing packet; final alerts equal offline except `reported_at`; 0 kernel drops; Zeek 1225/1225 |

All sixteen are pinned by `eval/lab/real_regression.py --zeek` (packets,
flows, flow states, final alerts, Zeek equality or the pinned exp09
difference); it passed on this branch. live-syn-01 and benign-01 used a build
of commit `a845dea`, everything from exp02 on a lab kit of `8a7f181`; the
analysis above is the current code's. Captures from exp05 on also hold the lab
bridge's own HTTP control connections on TCP 8766 and (from exp06) 8767 (no
alerts), including an access token in clear text: they are not shareable as
they are, and the token should be rotated after the lab work.

Lab kit override, for exp14 only: on the Ubuntu VM `victim_volume_burst.py`
was replaced by the version of commit `8b43717` (paced at 4 MB/s; SHA-256
`54f5802e…61fc9d72`, previously `1a25f5de…772bece1`), while the rest of the
kit stays `8a7f181`. The kit's own `SHA256SUMS` therefore no longer describes
that one file on the VM; the replacement and both hashes are recorded in the
lab transfer (`volume-update-proof.json`) and were checked against the
repository. That configuration (4 MiB/s, tcpdump's default buffer) is the
**failed exp14 run 01**: 9945 of 59091 packets dropped by the kernel, so it is
not counted (EVALUATION.md § 6). For the retry the owner replaced the upload
helper and `victim-capture.sh` on the VM with a local variant (1 MiB/s, 64 MiB
tcpdump buffer; SHA-256 `cddb1d41…` and `32f29430…`, recorded in
`retry-update-proof.json`). The repository's helpers now default to the same
rate and buffer but are not byte-identical to that variant (`a993fcfc…` and
`d39c2bd8…`).

## Not verified, or not met

- Precision/recall on real traffic: one run per experiment, so no rate.
- The baseline experiment (exp14: NG-RATE-001, NG-VOL-001) is not measured:
  run 01 failed on kernel drops, the retry's result is not in. Task 8.17
  (partial first baseline interval) is open
  ([eval/lab/RUN.md](../eval/lab/RUN.md)).
- Live early-warning delay: one run of one scan type, not a guarantee.
- False-positive rate on real networks: the benign hour is one narrow traffic
  mix, not a rate.
- Long runs (more than 1 h), high traffic on a live interface.
- The tag-triggered release workflow (draft creation) has never run.
- systemd unit on a real host (`systemd-analyze` only).

## Remaining steps for the owner

1. Finish exp14 and transfer it; rotate the lab bridge's token afterwards.
2. Review and merge pull request #8, then #9.
3. Decide on the tag `v1.0.0rc1` (private draft pre-release) and, after the
   lab results, on `v1.0.0` and on repository visibility.
