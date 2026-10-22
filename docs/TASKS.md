# Task board

The current phase's work items. Planning, phase order and exit criteria live
in [ROADMAP.md](../ROADMAP.md); task numbers here match it.
👤 = needs the user (physical lab, account settings or a publishing decision).

## Done

- [x] Phase 0 — foundation, tooling, CI, ADR 0001–0003 (v0.1.0)
- [x] Phase 1 — ingestion and protocol analysis (v0.1.0; own pcap/pcapng readers, fast decoder and new packet fields in v0.2.0)
- [x] Phase 2 — flows and feature extraction (v0.2.0)
- [x] Phase 3 — detection engine (v0.3.0): TRW, UDP scan, SYN flood, DNS tunnel, NXDOMAIN/DGA, fragmentation, connection-rate and volume baselines; `netguard rules`; ADR 0006–0007; learning notes 03–04
- [x] Phase 4 — backend, persistence and API (v0.4.0): SQLite store, job runner with isolated workers, REST API v1, ECS export; ADR-0008; learning note 05
- [x] Phase 5 — web dashboard (v0.5.0 = MVP): React/TypeScript SPA, rule profiles, HTML report, CSV export; ADR-0009; learning note 06
- [x] Phase 6 — live capture and replay (v0.6.0): `netguard monitor`, `netguard replay`, early warnings, max incident age, detection-delay benchmark; ADR-0010; learning note 07
- [x] Phase 7 — advanced detection (v0.7.0): explainable confidence, alert correlation, DHCP lease correlation, profile TOML import/export, `netguard config`; ADR-0011; learning note 08

Deferred (ADR-0011): Zeek/Suricata input, ICMP tunnel rule, resolver policy, seasonal baselines; ML rejected for now.

## Now: Phase 9, hardening and CI/CD (Phase 8 lab work waits on the user)

- [ ] **9.1** Threat-model review of every input path (captures, API, uploads, profiles, dashboard)
- [ ] **9.2** Dependency audit (`pip-audit`), license inventory, SBOM
- [ ] **9.3** CI: security checks (pip-audit, pnpm audit, ruff `S`), release workflow that builds the dashboard into the wheel
- [ ] **9.4** Installation and deployment check from a clean environment (wheel install, `netguard serve` on Ubuntu)
- [ ] **9.5** Secure defaults review (limits, timeouts, headers, permissions) and documentation

## Waiting on the user 👤

- [ ] **8.3** Build the UTM lab: Kali (attacker) + Ubuntu (victim) on an isolated host-only network ([LAB_SETUP.md](LAB_SETUP.md))
- [ ] **6.5** Live capture on a real interface: `netguard monitor -i <iface> --write live.pcap` during lab attacks; compare with `netguard analyze live.pcap`; note kernel drops ([LIVE_CAPTURE.md](LIVE_CAPTURE.md))
- [ ] **8.4** Capture attack traffic (`nmap -sS/-sT/-sX/-sN/-sF/-sU/-sn`, `-T1`, `masscan`, `arp-scan`, `bettercap arp.spoof`) and ≥ 1 h of benign traffic into `captures/` (git-ignored)
- [ ] **2.11** On those captures: `netguard flows` state distribution for `nmap -sS`, compared with Zeek `conn.log`
- [ ] On lab captures: `nmap -sS -T1`, `nmap -sU`, `nmap -f`, `hping3 -S --flood` (isolated lab only) to validate NG-SCAN-002/003, NG-FRAG-001, NG-SYN-001
- [ ] Re-check every confidence factor on real lab captures (Phase 8); remove factors that do not separate true from false positives
- [ ] Work through the questions in learning notes 01–08

## Known issues

Tracked with their target phase in [ROADMAP.md § 8](../ROADMAP.md#8-bilinen-sorunlar).
