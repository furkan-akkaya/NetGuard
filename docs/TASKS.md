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
- [x] **10.4** v1.0 checklist against the Definition of Done ([RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md)): 8/12 met, so no v1.0.0 yet; release steps rehearsed locally and, on pull requests, by `release-dryrun.yml`
- [x] **10.8** Release candidate prepared: version `1.0.0rc1` in all three places, CHANGELOG section used as release notes, install/verify/uninstall guide ([DEPLOYMENT.md](DEPLOYMENT.md)), delivery report ([DELIVERY_REPORT.md](DELIVERY_REPORT.md)); artefacts rehearsed by `release-dryrun.yml`. Not tagged
- [x] **10.5** Publication: PR #8-#12 merged, `v1.0.0rc2` tagged (draft only), repository public, `v1.0.0rc3` tagged and published as a verified pre-release ([PUBLICATION_RC3.md](PUBLICATION_RC3.md)); `v1.0.0` only after the field plan
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
- [x] **8.11a** Live-interface SYN measurement (live-syn-01, 90 s, 0 kernel drops reported): live final alerts == offline except `reported_at`; flow states == Zeek 8.2.2 (1000/1000)
- [x] **8.11b** 1 h benign baseline + RSS (benign-01, build of `a845dea`): 3640 s, 4245 packets, 0 kernel drops; live 0 = offline 0 final alerts; peak RSS 34.0 MiB; flow states vs Zeek 8.2.2 396/397, differences explained. One low-rate SSH-banner/ping mix, not a production FP rate ([EVALUATION.md § 6](EVALUATION.md))
- [x] **8.11c** Live delay with early warnings on (live-early-01, 120 s, 0 kernel drops): early warnings 0.683 s (NG-SCAN-001) and 0.757 s (NG-SCAN-002) after the threshold-crossing packet; final alerts equal offline except `reported_at`. One run, one scan type ([EVALUATION.md § 6](EVALUATION.md)); `live_delay.py --pcap` now replays the capture to find the crossing
- [ ] **8.12** 👤 Remaining attack experiments: connect (r02), Xmas, FIN, NULL, UDP, sweep, frag and SYN burst done on 27 Oct 2026 (each exactly its declared detections; [EVALUATION.md § 6](EVALUATION.md)); slow scan exp06 done too (NG-SCAN-002 only, as declared). All attack experiments of 8.12 measured once each
- [x] **8.17** Resolved in 1.0.0rc2: discard first partial and EOF intervals, count only complete intervals for learning and warm-up. See BASELINE_INTERVALS.md; fixed-window splitting remains a limit.
- [x] **8.16** Connections without a SYN (NULL/FIN/Xmas probes) follow Zeek's endpoint states (`RSTRH`/`RSTR`/`SH` instead of `OTH`): 17 cases checked against Zeek 8.2.2, regression test from the real probes, exp03-exp05 now equal to Zeek; no alert changes. exp09's difference is the documented no-reassembly limit, pinned by size
- [x] **8.14** Flow state: an RST after the FIN exchange was RSTO, Zeek says SF (seen once in benign-01). Now follows Zeek's endpoint rules for FIN/RST order (ADR-0004); regression test from the real connection, 14 orderings checked against Zeek 8.2.2; benign-01 397/397 TCP/UDP flows match, equal with Zeek's DNS timeout at 60 s
- [x] **8.15** Flow state when both endpoints reset now follows Zeek (RSTR, or REJ without payload). The REJ *label* does not feed the detectors (they use connection events; pinned by a test); 33 orderings and pre-handshake cases checked against Zeek 8.2.2; real-capture regression unchanged (`eval/lab/real_regression.py`)
- [x] **8.13** ARP, DNS and baseline rules: exp11 (NG-ARP-001), exp12 (NG-DNS-002, 40/40 NXDOMAIN) and exp13 (NG-DNS-001) measured, each exactly as declared; exp14: run 01 failed (9945 of 59091 packets dropped by the kernel; not counted), **r02 accepted** (0 drops; raw capture: NG-RATE-001 and NG-VOL-001 with the declared entities; Zeek 2331/2331), run with the owner's local helper variant (1 MiB/s, 64 MiB buffer; not byte-identical to the repository's helpers, which now default to the same values with bounded `--rate` and `NG_CAPTURE_BUFFER_KIB`)
- [ ] **9.5** Run `deploy/netguard.service` under systemd on the Ubuntu server ([DEPLOYMENT.md](DEPLOYMENT.md))
- [x] **6.5** Live capture on a real interface: done on the lab VM in live-syn-01 and benign-01 (`monitor --sudo --write`, compared with offline analysis, kernel drops recorded); see 8.11a/b
- [ ] **8.4** Capture attack traffic (`nmap -sS/-sT/-sX/-sN/-sF/-sU/-sn`, `-T1`, `masscan`, `arp-scan`, `bettercap arp.spoof`) and ≥ 1 h of benign traffic into `captures/` (git-ignored)
- [x] **2.11** `nmap -sS` state distribution compared with Zeek `conn.log` on real captures (exp01 1001/1001, live-syn-01 1000/1000)
- [ ] On lab captures: `nmap -sS -T1`, `nmap -sU`, `nmap -f`, a bounded `hping3 -S` burst (isolated lab only) to validate NG-SCAN-002/003, NG-FRAG-001, NG-SYN-001 (part of 8.12)
- [ ] Re-check every confidence factor on real lab captures (Phase 8); remove factors that do not separate true from false positives
- [ ] Work through the questions in learning notes 01–08

## Known issues

Tracked with their target phase in [ROADMAP.md § 8](../ROADMAP.md#8-bilinen-sorunlar).

## 30 October 2026 release follow-up

Task 8.17 is resolved by the complete-interval policy in BASELINE_INTERVALS.md. Long live and repeated load validation remain open. PR #8 and #9 are merged; PR #10 content is included in the RC2 branch.
