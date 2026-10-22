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

Deferred to Phase 7 until they show measurable value: ICMP tunnel/payload rule, unapproved-resolver policy.

## Now: Phase 7, advanced detection

Each candidate is evaluated for measurable value before it is built.

- [ ] **7.1** Alert correlation: group overlapping alerts (NG-SCAN-001 + NG-SCAN-002 + NG-RATE-001 on one source) into one incident view
- [ ] **7.2** Explainable confidence score per alert (which evidence raised or lowered it)
- [ ] **7.3** DHCP correlation to suppress the `dhcp_reassignment` ARP false positive
- [ ] **7.4** Rule import/export (profiles as TOML/JSON files)
- [ ] **7.5** Optional inputs: Zeek `conn.log` / Suricata EVE JSON
- [ ] **7.6** Re-evaluate the deferred ICMP tunnel and resolver-policy rules against lab data

## Waiting on the user 👤

- [ ] **8.3** Build the UTM lab: Kali (attacker) + Ubuntu (victim) on an isolated host-only network ([LAB_SETUP.md](LAB_SETUP.md))
- [ ] **6.5** Live capture on a real interface: `netguard monitor -i <iface> --write live.pcap` during lab attacks; compare with `netguard analyze live.pcap`; note kernel drops ([LIVE_CAPTURE.md](LIVE_CAPTURE.md))
- [ ] **8.4** Capture attack traffic (`nmap -sS/-sT/-sX/-sN/-sF/-sU/-sn`, `-T1`, `masscan`, `arp-scan`, `bettercap arp.spoof`) and ≥ 1 h of benign traffic into `captures/` (git-ignored)
- [ ] **2.11** On those captures: `netguard flows` state distribution for `nmap -sS`, compared with Zeek `conn.log`
- [ ] On lab captures: `nmap -sS -T1`, `nmap -sU`, `nmap -f`, `hping3 -S --flood` (isolated lab only) to validate NG-SCAN-002/003, NG-FRAG-001, NG-SYN-001
- [ ] Work through the questions in learning notes 01–04

## Known issues

Tracked with their target phase in [ROADMAP.md § 8](../ROADMAP.md#8-bilinen-sorunlar).
