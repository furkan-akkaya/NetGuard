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
- [x] Phase 9 — hardening and CI/CD (v0.8.0): threat model and 7 fixes, dependency audit and SBOM, security CI job, release workflow, clean-install and Linux container verification, systemd unit; learning note 09

Deferred (ADR-0011): Zeek/Suricata input, ICMP tunnel rule, resolver policy, seasonal baselines; ML rejected for now.

## Now: Phase 10, documentation, release and portfolio (Phase 8 lab work waits on the user)

- [x] **10.1** Code-quality review across modules: detector state losses now reported, dead code and an unused dependency removed
- [x] **10.2** Engineering evaluation report ([ENGINEERING_REPORT.md](ENGINEERING_REPORT.md)); limitations table and benchmarks brought up to date
- [x] **10.3** Screenshots and CLI demo from real analyses of the synthetic scenarios ([DEMO.md](DEMO.md)); fixed the traffic chart they exposed
- [x] **10.4** v1.0 checklist against the Definition of Done ([RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md)): 8/12 met, so no v1.0.0 yet; release steps dry-run locally
- [ ] **10.5** 👤 Decide: tag `v1.0.0rc1` to verify the release workflow (draft pre-release, stays private); later `v1.0.0` after the lab; repository visibility
- [x] **10.6** LinkedIn (EN/TR), CV and interview drafts with measured claims only ([PORTFOLIO.md](PORTFOLIO.md))
- [x] **10.7** Fixes from the external audit (27 Oct 2026): concurrent upload quota, full Origin check (`--allowed-origin`), bounded live alert history, time-series bound, release gates (tagged-source checks, locked install = SBOM, sdist coverage)
- [x] **8.5** Lab tooling without the lab: `lab evaluate --manifest`, `lab compare-flows` (Zeek), acceptance criteria fixed in advance ([LAB_SETUP.md § 8](LAB_SETUP.md))

## Waiting on the user 👤

- [x] **8.3** UTM lab network (reported by the user, 27 Oct 2026): Kali 10.77.0.10 ↔ Ubuntu VM 10.77.0.20 on one named Host Network (UTM 5.0.8), ping 3/3; no route to the Mac or internet. The physical server stays out of attack traffic
- [x] **8.6** Lab scripts ([eval/lab/](../eval/lab/)): victim capture, experiment 01 (SYN scan), ingest into the manifest; ground truth for exp01 and benign-01 written before any run; scripts exercised in a container (not a lab result)
- [x] **8.7** Ubuntu VM checked by the user (27 Oct 2026): Ubuntu 26.04.1 LTS, Python 3.14.4, tcpdump installed, SSH active
- [x] **8.8** Transfer channel in use (UTM VirtFS share); experiment 01 captured and transferred
- [x] **8.9** First real capture measured (exp01 SYN scan, hash-verified): NG-SCAN-001 + NG-SCAN-002 with declared entities, 0 FP; flow states == real Zeek 8.2.2 conn.log (1001/1001); replay == offline final alerts. One capture, not tool-wide precision/recall. See [EVALUATION.md § 6](../docs/EVALUATION.md)
- [x] **8.10** Runners for the remaining experiments (`eval/lab/kali-run.sh`), benign + RSS live runner (`victim-live-rss.sh`), live-vs-offline and Zeek helpers; container-tested
- [ ] **8.11** 👤 1 h benign baseline + RSS, and a live-interface SYN measurement with kernel-drop accounting (user running; a 90 s live SYN run already done, pcap/jsonl transferring)
- [ ] **8.12** 👤 Remaining attack experiments (connect/XMAS/FIN/NULL/slow/UDP/sweep/frag/SYN-burst) via `kali-run.sh`; then precision/recall over all lab attacks
- [ ] **8.13** Open (needs lab changes): NG-ARP-001 (a third address to impersonate), NG-DNS-001/002 (a resolver on the victim), NG-RATE-001/NG-VOL-001 (>=10 min baseline then a change)
- [ ] **9.5** Run `deploy/netguard.service` under systemd on the Ubuntu server ([DEPLOYMENT.md](DEPLOYMENT.md))
- [ ] **6.5** Live capture on a real interface (loopback already verified in an Ubuntu container): `netguard monitor -i <iface> --write live.pcap` during lab attacks; compare with `netguard analyze live.pcap`; note kernel drops ([LIVE_CAPTURE.md](LIVE_CAPTURE.md))
- [ ] **8.4** Capture attack traffic (`nmap -sS/-sT/-sX/-sN/-sF/-sU/-sn`, `-T1`, `masscan`, `arp-scan`, `bettercap arp.spoof`) and ≥ 1 h of benign traffic into `captures/` (git-ignored)
- [ ] **2.11** On those captures: `netguard flows` state distribution for `nmap -sS`, compared with Zeek `conn.log`
- [ ] On lab captures: `nmap -sS -T1`, `nmap -sU`, `nmap -f`, `hping3 -S --flood` (isolated lab only) to validate NG-SCAN-002/003, NG-FRAG-001, NG-SYN-001
- [ ] Re-check every confidence factor on real lab captures (Phase 8); remove factors that do not separate true from false positives
- [ ] Work through the questions in learning notes 01–08

## Known issues

Tracked with their target phase in [ROADMAP.md § 8](../ROADMAP.md#8-bilinen-sorunlar).
