# Task board

The current phase's work items. Larger planning lives in [ROADMAP.md](ROADMAP.md).
When the project is on GitHub, each open item becomes an issue and this file
links to it.

Owner: **F** = Furkan (learning-critical, hands-on), **C** = shared/assisted.

## Done (Phase 0–1, v0.1.0)

- [x] Project scaffolding, tooling, CI (C)
- [x] Decoder, stream reader, engine (C)
- [x] `portscan`, `hostsweep`, `arpspoof` detectors (C)
- [x] Lab scenarios + evaluation harness (C)
- [x] Documentation: README, architecture, ADRs, evaluation, learning note 01 (C)

## Next: Phase 2

### Setup
- [x] **2.0** Create the GitHub repository (private) and push `main` (F)
- [ ] **2.1** Build the UTM lab: Kali (attacker) + Ubuntu (victim) on an isolated host-only network ([LAB_SETUP.md](LAB_SETUP.md)) (F)

### Validation
- [ ] **2.2** Capture `nmap` scans with each scan type and timing template; save under `captures/` (git-ignored) (F)
- [ ] **2.3** Capture 1 h of benign traffic; measure alerts per hour (F)
- [ ] **2.4** Add `docs/EVALUATION.md § Real captures` with the results (C)

### Detection
- [ ] **2.5** Work through the lab questions in learning note 01 (F)
- [ ] **2.6** Design review: TRW scan detector (we write the design doc together, then implement) (C)
- [ ] **2.7** UDP scan detection (C)
- [ ] **2.8** DNS tunneling detector, built by Furkan from a guided spec and tests (F)

## Known issues

- `passive_ftp` false positive: SYN counting ignores successful handshakes (→ 2.6 TRW)
- `slow_scan` evasion: 60 s window (→ Phase 2.5)
- `dhcp_reassignment` false positive in `arpspoof` (→ DHCP correlation, Phase 3)
- pcapng files with several interfaces of *different* link types use the first interface's link type
