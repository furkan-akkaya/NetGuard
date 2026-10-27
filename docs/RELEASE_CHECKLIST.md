# v1.0 release checklist

The brief defines when NetGuard v1.0 is complete ("Definition of Done") and
says: if a major requirement cannot be met, explain the limitation and do not
claim complete compliance. This page checks each item against evidence.
Reviewed in Phase 10 (October 2026) on `feat/release-prep`.

Status: ✅ met · 🟡 partly met (what is missing is named) · ❌ not met yet

| # | Definition of Done | Status | Evidence | Missing |
|---|---|---|---|---|
| 1 | Documented core features genuinely work | ✅ | 325 Python and 14 dashboard tests in CI; every CLI command, API route and dashboard page exercised against real analyses ([DEMO.md](DEMO.md)) | — |
| 2 | Packet and flow processing are verified | 🟡 | Reader and decoder tests, differential fuzzing against dpkt, flow-state tests, 27 scenarios; on two real lab captures every flow matched Zeek 8.2.2 on endpoints, direction and state (1001/1001 and 1000/1000) | Both real captures are TCP SYN scans: UDP, payload-carrying and long-lived flows have not been compared with Zeek yet |
| 3 | Detection rules have reproducible tests | ✅ | Unit tests per rule; attack and benign look-alike scenarios with pinned TP/FP/FN (`tests/test_scenarios.py`); `netguard lab evaluate` | — |
| 4 | Alerts include meaningful supporting evidence | ✅ | Summary, structured evidence with thresholds, confidence factors, ATT&CK mapping; contract pinned by `test_alert_contract_v1` | — |
| 5 | Backend, frontend and reporting are integrated | ✅ | One package: API serves the dashboard; HTML report, NDJSON/ECS and CSV exports from the API and the dashboard | — |
| 6 | Offline capture analysis works reliably | ✅ | Bounded readers, malformed input counted not fatal, worker isolation with time/memory limits, clean installs on macOS and Ubuntu | — |
| 7 | Live capture works in supported authorized environments, limitations documented | 🟡 | One 90 s live run on the lab VM's real interface (`monitor --sudo`, normal user): 0 kernel drops reported, live final alerts equal offline analysis of the written pcap except `reported_at` ([EVALUATION.md § 6](EVALUATION.md)); [LIVE_CAPTURE.md](LIVE_CAPTURE.md) | No long run yet: the 1 h benign/RSS run has started but has no result |
| 8 | Performance and detection limitations are measured | 🟡 | Throughput, memory, flood behaviour, detection delay, synthetic scorecard ([EVALUATION.md](EVALUATION.md)); first real captures (two SYN scans: both scan rules fired, 0 FP) | Only one attack type on real traffic; no benign false-positive rate, live delay with early warnings or memory over a long live run yet |
| 9 | Automated tests and quality checks pass | ✅ | CI: lint, strict typing, tests on 2 OS × 4 Python versions, coverage gate, dashboard build and tests, dependency audit, license gate | Re-check on the final release commit |
| 10 | Security-sensitive defaults are reviewed | ✅ | [THREAT_MODEL.md](THREAT_MODEL.md): 7 Phase 9 fixes, plus 4 defects found by the external audit of 27 Oct 2026 (concurrent quota, Origin port, live alert history, time-series bound), each fixed with a regression test | The audit showed the Phase 9 review missed cases: review again on the release commit |
| 11 | Documentation reflects the actual implementation | ✅ | Phase 10 review corrected stale content (limitations table, drop counters, protocol list); [ENGINEERING_REPORT.md](ENGINEERING_REPORT.md) | Re-read once more on the release commit |
| 12 | GitHub release artifacts are verified | 🟡 | The release gates ran on GitHub without a tag in `release-dryrun.yml` (run 40493284720, commit `8923b0c`, all steps green): version fields, lint/types/tests/coverage, audit and licenses, sdist holding only tracked files and rebuilding the dashboard and tests, wheel installed with the locked dependencies, SBOM. The downloaded artefacts pass `SHA256SUMS`, and the SBOM lists the same 15 versions as the locked requirements | The tag-triggered `release.yml` itself (draft release creation) has never run: needs a tag (task 10.5) |

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
