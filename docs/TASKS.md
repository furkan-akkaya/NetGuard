# Task board

The current phase's work items. Planning, phase order and exit criteria live
in [ROADMAP.md](../ROADMAP.md); task numbers here match it.
When the project is on GitHub, each open item becomes an issue and this file
links to it.

Owner: **F** = Furkan (learning-critical, hands-on), **C** = shared/assisted.

## Done (Phase 0–1, v0.1.0)

- [x] Project scaffolding, tooling, CI (C)
- [x] Decoder, stream reader, engine (C)
- [x] `portscan`, `hostsweep`, `arpspoof` detectors (C)
- [x] Lab scenarios + evaluation harness (C)
- [x] Documentation: README, architecture, ADRs, evaluation, learning note 01 (C)

## Now: Phase 2, lab and real-traffic validation

- [x] **2.0** Create the GitHub repository and push `main` (F)
- [ ] **2.1** Build the UTM lab: Kali (attacker) + Ubuntu (victim) on an isolated host-only network ([LAB_SETUP.md](LAB_SETUP.md)) (F)
- [ ] **2.2** Capture attack traffic: `nmap` scan types and timing templates, `masscan`, `arp-scan`, `bettercap`; save under `captures/` (git-ignored) (F)
- [ ] **2.3** Capture ≥ 1 h of benign traffic (F)
- [ ] **2.4** Real-capture manifest `eval/captures.toml` (sha256, tool, command, expected alerts) (C)
- [ ] **2.5** `netguard lab evaluate --manifest … [-c config]`; raise `lab/evaluate.py` coverage (C)
- [ ] **2.6** `docs/EVALUATION.md § Real captures` with the results (C)
- [ ] **2.7** Work through the lab questions in learning note 01 (`docs/learning/answers-01.md`) (F)

## Next: Phase 3, flow analysis and alert model

See [ROADMAP.md § Faz 3](../ROADMAP.md#faz-3--flow-analizi-trafik-istatistikleri-ve-alarm-modeli--v020).

## Known issues

Tracked with their target phase in [ROADMAP.md § 7](../ROADMAP.md#7-bilinen-sorunlar-ve-hedef-fazları).
