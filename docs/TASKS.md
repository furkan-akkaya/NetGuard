# Task board

The current phase's work items. Planning, phase order and exit criteria live
in [ROADMAP.md](../ROADMAP.md); task numbers here match it.
👤 = needs the user (physical lab, account settings or a publishing decision).

## Done

- [x] Phase 0 — foundation, tooling, CI, ADR 0001–0003 (v0.1.0)
- [x] Phase 1 — ingestion and protocol analysis (v0.1.0; own pcap/pcapng readers, fast decoder and new packet fields in v0.2.0)
- [x] Phase 2 — flows and feature extraction (v0.2.0): flow table, `conn_state`, retransmissions, timeout classes, `netguard flows`, flow statistics, alert model v1, rule catalog, tracker DoS fix, ADR 0004–0005, learning note 02

## Now: Phase 3, detection engine

- [ ] **3.1** DNS decoder: all questions, `qtype`, responses, `rcode`, answer count, query/response matching by id; DNS statistics
- [ ] **3.2** TRW scan detector on flow outcomes; compare with the window detector; ADR
- [ ] **3.3** UDP scan detection (ICMP port unreachable as the "closed" signal)
- [ ] **3.4** Slow-scan detection (long horizon, memory budget)
- [ ] **3.5** SYN flood detector (S0 ratio, SYN rate, source diversity)
- [ ] **3.6** ICMP anomalies
- [ ] **3.7** DNS anomalies: tunnelling indicators, NXDOMAIN/DGA ratio, unapproved resolvers
- [ ] **3.8** Unusual connection frequency (EWMA baseline, robust deviation)
- [ ] **3.9** Abnormal traffic volume per host
- [ ] **3.10** IP fragment anomalies
- [ ] **3.11** Scenario + benign look-alike + rule page for every rule
- [ ] **3.12** Per-rule enable/thresholds in TOML, `netguard rules`, configurable detector `max_keys`

## Waiting on the user 👤

- [ ] **8.3** Build the UTM lab: Kali (attacker) + Ubuntu (victim) on an isolated host-only network ([LAB_SETUP.md](LAB_SETUP.md))
- [ ] **8.4** Capture attack traffic (`nmap -sS/-sT/-sX/-sN/-sF/-sU/-sn`, `-T1`, `masscan`, `arp-scan`, `bettercap arp.spoof`) and ≥ 1 h of benign traffic into `captures/` (git-ignored)
- [ ] **2.11** On those captures: `netguard flows` state distribution for `nmap -sS`, compared with Zeek `conn.log`
- [ ] Work through the questions in learning notes 01 and 02

## Known issues

Tracked with their target phase in [ROADMAP.md § 8](../ROADMAP.md#8-bilinen-sorunlar).
