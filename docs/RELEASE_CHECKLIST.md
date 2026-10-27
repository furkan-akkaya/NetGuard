# v1.0 release checklist

The brief defines when NetGuard v1.0 is complete ("Definition of Done") and
says: if a major requirement cannot be met, explain the limitation and do not
claim complete compliance. This page checks each item against evidence.
Reviewed in Phase 10 (October 2026) on `feat/release-prep`; re-checked on 27 October 2026 for the `1.0.0rc1` candidate on `fix/audit-2026-10-27` ([DELIVERY_REPORT.md](DELIVERY_REPORT.md)).

Status: ✅ met · 🟡 partly met (what is missing is named) · ❌ not met yet

| # | Definition of Done | Status | Evidence | Missing |
|---|---|---|---|---|
| 1 | Documented core features genuinely work | ✅ | 425 Python and 14 dashboard tests in CI; every CLI command, API route and dashboard page exercised against real analyses ([DEMO.md](DEMO.md)) | — |
| 2 | Packet and flow processing are verified | 🟡 | Reader and decoder tests, differential fuzzing against dpkt, flow-state tests, 27 scenarios; on two real SYN-scan captures every flow matched Zeek 8.2.2 on endpoints, direction and state (1001/1001 and 1000/1000); on the 1 h benign capture all 397 NetGuard flows match after fixing the FIN-then-RST state (task 8.14); Zeek's two extra mDNS flows come from its 10 s DNS session timeout, and with that set to 60 s the comparison is equal ([EVALUATION.md § 6](EVALUATION.md)); thirteen further real captures equal to Zeek (exp03-exp05 after fixing the states of connections without a SYN, task 8.16; exp13 with Zeek's attempt timeout at NetGuard's 30 s), exp09 differs by design (no fragment reassembly); every flow state rule checked against Zeek 8.2.2 case by case (50 cases); sixteen real captures pinned by `eval/lab/real_regression.py --zeek` | SSH payload compared only by flow state; fragmented traffic not reassembled (documented limit) |
| 3 | Detection rules have reproducible tests | ✅ | Unit tests per rule; attack and benign look-alike scenarios with pinned TP/FP/FN (`tests/test_scenarios.py`); `netguard lab evaluate` | — |
| 4 | Alerts include meaningful supporting evidence | ✅ | Summary, structured evidence with thresholds, confidence factors, ATT&CK mapping; contract pinned by `test_alert_contract_v1` | — |
| 5 | Backend, frontend and reporting are integrated | ✅ | One package: API serves the dashboard; HTML report, NDJSON/ECS and CSV exports from the API and the dashboard | — |
| 6 | Offline capture analysis works reliably | ✅ | Bounded readers, malformed input counted not fatal, worker isolation with time/memory limits, clean installs on macOS and Ubuntu | — |
| 7 | Live capture works in supported authorized environments, limitations documented | 🟡 | Three live runs on the lab VM's real interface (`monitor --sudo`, normal user): a 90 s SYN scan and 1 h of benign traffic (build of `a845dea`), and a 120 s SYN scan with early warnings (`8a7f181`); all 0 kernel drops reported and live final alerts equal to offline analysis of the written pcap; 1 h run peaked at 34.0 MiB RSS ([EVALUATION.md § 6](EVALUATION.md)); [LIVE_CAPTURE.md](LIVE_CAPTURE.md) | Only low-rate traffic on one lab host pair; no run longer than 1 h or under load |
| 8 | Performance and detection limitations are measured | 🟡 | Throughput, memory, flood behaviour, detection delay, synthetic scorecard ([EVALUATION.md](EVALUATION.md)); real captures: SYN, connect, Xmas, FIN, NULL, slow and UDP scans, ping sweep, fragmented scan, SYN burst, ARP binding change, DNS NXDOMAIN and tunnel-like names each raised exactly the declared detections with no other alert; live early warnings 0.68-0.76 s after the threshold-crossing packet; 1 h of low-rate benign lab traffic: 0 alerts, 34.0 MiB peak RSS | One run per experiment on one lab host pair: not a precision/recall or false-positive rate for real networks; baseline rules (exp14) not measured: run 01 failed on 9945 kernel drops, retry pending |
| 9 | Automated tests and quality checks pass | ✅ | CI: lint, strict typing, tests on 2 OS × 4 Python versions, coverage gate, dashboard build and tests, dependency audit, license gate | Re-check on the final release commit |
| 10 | Security-sensitive defaults are reviewed | ✅ | [THREAT_MODEL.md](THREAT_MODEL.md): 7 Phase 9 fixes, plus 4 defects found by the external audit of 27 Oct 2026 (concurrent quota, Origin port, live alert history, time-series bound), each fixed with a regression test | The audit showed the Phase 9 review missed cases: review again on the release commit |
| 11 | Documentation reflects the actual implementation | ✅ | Phase 10 review corrected stale content (limitations table, drop counters, protocol list); [ENGINEERING_REPORT.md](ENGINEERING_REPORT.md); install/verify/uninstall guide ([DEPLOYMENT.md](DEPLOYMENT.md)); [DELIVERY_REPORT.md](DELIVERY_REPORT.md) | Re-read once more on the release commit |
| 12 | GitHub release artifacts are verified | 🟡 | The release gates ran on GitHub without a tag in `release-dryrun.yml` (run 40493284720, commit `8923b0c`, all steps green; it re-runs on every push to pull request #9, now with version `1.0.0rc1`): version fields, lint/types/tests/coverage, audit and licenses, sdist holding only tracked files and rebuilding the dashboard and tests, wheel installed with the locked dependencies, SBOM. The downloaded artefacts pass `SHA256SUMS`, and the SBOM lists the same 15 versions as the locked requirements | The tag-triggered `release.yml` itself (draft release creation) has never run: needs a tag (task 10.5) |

## Verdict

**NetGuard does not meet the Definition of Done yet**, so it should not be
tagged v1.0.0. Three items depend on the lab (2, 7, 8) and one on a release
run (12). "8 of 12" is a count of checklist rows, not a completion
percentage: the open items need the most field work, and the 27 October
audit found defects in items already marked as met (now fixed). Work that
needs neither the lab nor a publishing decision is done as of that audit's
fixes.

## Recommended path

1. **Release candidate (verifies item 12 without claiming v1.0).** Set the
   version to `1.0.0rc1`, add a `## [1.0.0rc1]` changelog section, tag
   `v1.0.0rc1`. The workflow builds, smoke-tests and creates a **draft
   pre-release**; download its wheel and check `SHA256SUMS`. Nothing becomes
   public: a draft release is visible only to people with write access to
   the repository, which is private.
2. **Phase 8 lab (items 2, 7, 8).** Capture the attacks and ≥ 1 h of benign
   traffic in the UTM lab ([LAB_SETUP.md](LAB_SETUP.md)), run live capture on
   the lab interface, compare flow states with Zeek, add a "Real captures"
   section to EVALUATION.md with whatever the numbers turn out to be, and
   re-check the confidence factors.
3. **v1.0.0.** Fix what the lab shows, update the version and changelog, tag
   `v1.0.0`, verify the draft release, publish it.
4. **Visibility.** Making the repository public is a separate decision for
   the user. Before it: check that `git log -p` contains no captures, tokens
   or personal data (CI and `.gitignore` keep captures out; the history has
   only synthetic lab data generated by code).

## Release steps (for 10.5)

```bash
# on main, after merging the release branch
uv run pytest -q && pnpm --dir frontend test
# set the version in pyproject.toml, src/netguard/__init__.py and frontend/package.json
# (PEP 440, e.g. 1.0.0rc1), then add the CHANGELOG section
git commit -S -m "chore: release vX.Y.Z"
git tag -s vX.Y.Z -m "NetGuard vX.Y.Z"
git push origin main vX.Y.Z
gh run watch                       # the Release workflow
gh release view vX.Y.Z             # draft: check assets, notes, SHA256SUMS
```
