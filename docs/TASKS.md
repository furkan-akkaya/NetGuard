# Task board

The current phase's work items. Planning, phase order and exit criteria live
in [ROADMAP.md](../ROADMAP.md); task numbers here match it.
👤 = needs the user (physical lab, account settings or a publishing decision).

## Done

- [x] Phase 0 — foundation, tooling, CI, ADR 0001–0003 (v0.1.0)
- [x] Phase 1 — ingestion and protocol analysis (v0.1.0; own pcap/pcapng readers, fast decoder and new packet fields in v0.2.0)
- [x] Phase 2 — flows and feature extraction (v0.2.0)
- [x] Phase 3 — detection engine (v0.3.0): TRW, UDP scan, SYN flood, DNS tunnel, NXDOMAIN/DGA, fragmentation, connection-rate and volume baselines; `netguard rules`; ADR 0006–0007; learning notes 03–04

Deferred from Phase 3 to Phase 7 until they show measurable value: ICMP tunnel/payload rule, unapproved-resolver policy.

## Now: Phase 4, backend, persistence and API

- [ ] **4.1** ADR: storage and API stack (candidates: SQLite + FastAPI as optional `netguard[web]` extra)
- [ ] **4.2** Schema: captures, analysis jobs, flows, alerts, rules, stats; versioned migrations
- [ ] **4.3** Job lifecycle: queued → running → done/failed, cancellation, recovery of interrupted jobs
- [ ] **4.4** API v1: upload, analyse, search/sort/filter/paginate flows and alerts; OpenAPI
- [ ] **4.5** Event schema for SIEM export (ECS mapping)
- [ ] **4.6** Integration tests; upload size/type limits

## Waiting on the user 👤

- [ ] **8.3** Build the UTM lab: Kali (attacker) + Ubuntu (victim) on an isolated host-only network ([LAB_SETUP.md](LAB_SETUP.md))
- [ ] **8.4** Capture attack traffic (`nmap -sS/-sT/-sX/-sN/-sF/-sU/-sn`, `-T1`, `masscan`, `arp-scan`, `bettercap arp.spoof`) and ≥ 1 h of benign traffic into `captures/` (git-ignored)
- [ ] **2.11** On those captures: `netguard flows` state distribution for `nmap -sS`, compared with Zeek `conn.log`
- [ ] On lab captures: `nmap -sS -T1`, `nmap -sU`, `nmap -f`, `hping3 -S --flood` (isolated lab only) to validate NG-SCAN-002/003, NG-FRAG-001, NG-SYN-001
- [ ] Work through the questions in learning notes 01–04

## Known issues

Tracked with their target phase in [ROADMAP.md § 8](../ROADMAP.md#8-bilinen-sorunlar).
