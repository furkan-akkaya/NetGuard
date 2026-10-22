# ADR-0011: Phase 7 — which advanced features earn their place

- **Status:** Accepted
- **Date:** 2026-10-22

## Context

The brief lists candidates for Phase 7 (baselines, anomaly detection, tuning,
deduplication and correlation, explainable severity/confidence, integration
with other monitoring outputs, rule import/export) and requires each to show
measurable value first. The only labelled data available today are the 24
synthetic scenarios (real lab captures are pending, Phase 8). Measured on
v0.6.0:

| Observation | Number |
|---|---|
| Alerts on 13 attack scenarios | 19 for 15 attacker/target entities |
| Attack scenarios producing > 1 alert for one activity | 2 (`syn_scan_1000`: 2 rules; `arp_spoof_mitm`: 4 alerts) |
| Benign scenarios with a false positive | 3 of 11 |
| False positives distinguishable from true positives by alert count or severity | 0 of 3 |

## Decisions

| Candidate | Decision | Measurable value |
|---|---|---|
| **Explainable confidence** per alert | Build | Every alert gets a 5–95 score with the evidence factors that raised or lowered it. Value is measured as separation: confidence of true vs false positives on the scenarios. Factors are justified by protocol/attack knowledge in the rule pages, not fitted to scores. Because the same person wrote rules, factors and scenarios, this is reported as a consistency check, not accuracy. |
| **Alert correlation** into incidents | Build | Alerts about the same actor close in time become one incident with ATT&CK tactics. Measured as alerts → incidents per scenario, plus a multi-stage scenario. |
| **DHCP lease correlation** for ARP | Build | A binding change explained by a DHCP ACK from the established server is not reported. Measured on a new benign scenario with visible DHCP; the existing scenario without visible DHCP must stay a (documented) false positive. |
| **Rule/profile import and export** | Build | Profiles round-trip as TOML usable by `netguard analyze -c`; the documented example config is generated from the code. Functional value, small. |
| Zeek `conn.log` / Suricata EVE input | Defer (v1.x) | Value depends on real deployments that run those tools; no data to measure it here. |
| ICMP tunnel rule, unapproved-resolver policy | Defer | Unchanged since Phase 3: no scenario or lab data shows a gap the existing rules miss. |
| Seasonal baselines (time of day) | Defer | Needs days of stored history (Phase 4 stores analyses, not long-running baselines). |
| Machine-learning anomaly detection | Reject for now | No labelled real data to train or evaluate against; scores would not be explainable in the alert text. |

## Consequences

- Alert contract 1.2 adds an optional `confidence` object (additive).
- Correlation is a post-processing step over finished alerts (analysis
  results, API, dashboard); it does not change detection or the scorecard.
- The confidence numbers must be revisited on lab captures (Phase 8): a factor
  that does not separate true from false positives on real traffic is removed.
