# Confidence and correlation

Every alert carries an explainable **confidence** (5–95) and alerts are grouped
into **incidents**. Decisions: [ADR-0011](adr/0011-phase-7-feature-selection.md).
Code: `src/netguard/confidence.py`, `src/netguard/correlate.py`.

## Confidence

The rule says *what* was observed. Confidence says how strongly that evidence
points to malicious activity rather than a benign look-alike. Each rule starts
from a **base** that reflects how specific its signal is; each factor that
applies adds or subtracts a fixed **weight**. The score is clamped to 5–95,
because network evidence alone never proves intent or innocence. Levels:
`low` < 40 ≤ `medium` < 70 ≤ `high`.

The score is computed only from the alert's `evidence`, so it is reproducible
from the alert JSON. Every factor below is justified by how the attack or its
benign look-alike behaves on the wire; none was fitted to a score.

| Rule | Base | Factor | Weight | Why |
|---|---:|---|---:|---|
| NG-SCAN-001 | 60 | ≥ 90% of probed ports closed or silent | +20 | A user connects to services that exist; a scanner does not know what is there |
| | | Non-SYN probes (NULL/FIN/XMAS) | +15 | No legitimate client sends them |
| | | ≥ 100 ports | +10 | Breadth beyond any application's needs |
| | | > 50% of probed ports open | −25 | A client using real services (the remaining passive-FTP-like case) |
| NG-SCAN-002 | 65 | < 10% of first contacts succeeded | +20 | TRW's core signal at its strongest |
| | | ≥ 20 failed first contacts | +10 | More evidence, beyond the sequential test's minimum |
| | | ≥ 10 hosts and ≥ 10 ports | +5 | A broad scan |
| NG-SCAN-003 | 55 | ≥ 90% of UDP ports closed or silent | +20 | Same reasoning as TCP |
| | | ≥ 100 ports | +10 | |
| NG-SWEEP-001 | 55 | < 50% of probed addresses answered | +15 | Searching for hosts, not talking to known ones |
| | | ≥ 95% answered | −25 | A known inventory: monitoring systems poll hosts that exist |
| | | ≥ 100 hosts | +10 | |
| NG-ARP-001 | 50 | Binding flips between MACs | +25 | Two devices fighting over one IP is the MITM signature |
| | | Unsolicited reply | +15 | Poisoning tools send replies nobody asked for |
| | | Critical IP (e.g. gateway) | +10 | The usual MITM target |
| | | Single change via gratuitous ARP | −20 | What a newly connected device does |
| NG-SYN-001 | 60 | ≤ 1% of handshakes completed | +20 | Floods do not complete; busy servers do |
| | | Thousands of single-attempt sources | +10 | Spoofed sources |
| | | Target answered < 10% | −20 | An outage or filter looks the same |
| NG-DNS-001 | 55 | ≥ 50% TXT/NULL/CNAME/MX | +20 | Record types that carry data back to the client |
| | | Mean entropy ≥ 3.5 bits/char | +10 | Encoded data |
| | | ≥ 200 unique subdomains | +10 | Sustained transfer |
| NG-DNS-002 | 50 | ≥ 80% of names in different domains | +25 | DGA candidates are independent domains |
| | | Mean label entropy ≥ 3.0 | +10 | Generated rather than typed names |
| | | Failures in ≤ 2 domains | −25 | A wrong search suffix concentrates on one domain |
| NG-FRAG-001 | 60 | Transport header split across fragments | +25 | No normal IP stack fragments that way |
| NG-RATE-001, NG-VOL-001 | 40 | ≥ 20 × the host's baseline | +15 | Far outside the host's own range |
| | | Baseline from < 30 intervals | −10 | The baseline may not know this host's normal range yet |

### Measured (synthetic scenarios, v0.7.0)

All 5 false-positive alerts score 25–30 (low); all 22 true-positive alerts
score 45–95. Read this as a **consistency check**: the same person wrote the
rules, the factors and the scenarios. Phase 8 re-checks every factor on real
lab captures and removes any that does not separate true from false positives
there.

## Correlation into incidents

Alerts belong to one incident when they share their **actor** (the source; the
target for alerts without a source, such as a SYN flood) and their time spans
are at most 15 minutes apart (transitively). Early and final stages of one
alert count once. An incident reports the ATT&CK tactics its alerts cover in
kill-chain order, the highest severity and confidence, the rules and targets.

| Scenario | Alerts | Incidents |
|---|---:|---:|
| `syn_scan_1000` | 2 | 1 |
| `arp_spoof_mitm` | 4 | 1 |
| `compromised_workstation` | 4 | 1 (Defense Evasion → Discovery → Command and Control) |
| `monitoring_poller` (benign) | 3 | 1 |

Limits: the actor is an IP or, for ARP alerts, a MAC address; the same
attacker seen by both (scan alerts by IP, ARP spoofing by MAC) forms two
incidents. Correlation never adds or removes detections.

Where it appears: `netguard analyze` (text: an *Incidents* section; JSON:
`incidents`), the API (`/analyses/{id}/incidents`) and the dashboard's
analysis page.
