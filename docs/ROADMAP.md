# Roadmap

NetGuard grows in phases. Each phase must ship something that **works, is
tested and has measured results** before the next one starts. Phases 0–1 form
the MVP. Phase 2 onward is advanced.

Legend: ✅ done · 🔄 in progress · ⏳ planned

---

## Phase 0: Foundations ✅

**Goal:** a professional skeleton that makes the rest cheap.

- ✅ Repository, MIT license, `uv` project, `src/` layout
- ✅ Tooling: ruff (lint + format), mypy `--strict`, pytest + coverage
- ✅ GitHub Actions CI on Python 3.11 / 3.12 / 3.13
- ✅ Architecture document and ADRs 0001–0003
- ✅ Commit hygiene: a `commit-msg` hook that rejects AI co-author trailers

**Learning objectives:** Python packaging (`pyproject.toml`, entry points), why
strict typing helps a security tool, CI basics.

---

## Phase 1: MVP, offline detection pipeline ✅ (v0.1.0)

**Goal:** analyze a pcap and produce explainable alerts for reconnaissance
and L2 attacks.

- ✅ pcap/pcapng reader that works on non-seekable streams (stdin)
- ✅ Hardened decoder: Ethernet, Linux SLL, BSD loopback, raw IP; IPv4/IPv6; TCP/UDP/ICMP/ICMPv6/ARP; DNS query names
- ✅ Sliding-window distinct counter + incident aggregation (`window.py`)
- ✅ Detectors: `portscan` (SYN/NULL/FIN/XMAS), `hostsweep` (ICMP/ARP/TCP), `arpspoof`
- ✅ MITRE ATT&CK mapping, severity, evidence
- ✅ Text / JSON / JSONL output; TOML config with allowlist
- ✅ 11 labelled synthetic scenarios + evaluation harness; results locked by tests
- ✅ Fuzz-style robustness test for the decoder

**Exit criteria (met):** all attack scenarios except the documented slow-scan
evasion are detected. Every false positive is documented with its cause.
Coverage ≥ 90 %. CI is green.

**Learning objectives:** Ethernet/IP/TCP headers and TCP flags, the TCP
handshake and how scanners abuse it, ARP and why it is unauthenticated,
sliding windows and amortized O(1) analysis, false positives versus false
negatives, alert fatigue.
→ [learning/01-scan-detection.md](learning/01-scan-detection.md)

---

## Phase 2: Real-world validation & smarter scan detection ⏳

**Goal:** replace "works on synthetic data" with "measured on real captures",
and fix the known weaknesses.

| # | Task | Why |
|---|---|---|
| 2.1 | Build the UTM lab ([LAB_SETUP.md](LAB_SETUP.md)) and capture `nmap -sS/-sT/-sU/-sn/-sX/-T1`, `masscan`, `arp-scan`, `bettercap arp.spoof` | Real tool behaviour (timing, retransmits, decoys) differs from synthetic |
| 2.2 | Capture ≥ 1 h of *benign* lab traffic (updates, browsing, SSH, SMB) | We need a real false-positive baseline |
| 2.3 | Publish real-capture results in EVALUATION.md (alerts per hour on benign traffic, detection per tool/flag) | Honest measurement |
| 2.4 | **Threshold Random Walk (TRW)** scan detector (Jung et al., 2004) | Uses connection *outcomes*, which fixes the passive-FTP false positive; reaches decisions with fewer probes |
| 2.5 | Long-horizon slow-scan detection (e.g. a 1 h window with a lower threshold, or per-source distinct counts in a compact sketch) | Closes the `slow_scan` evasion |
| 2.6 | UDP scan detection (ICMP port-unreachable as the "closed" signal) | `nmap -sU` is invisible today |
| 2.7 | **DNS tunneling / DGA heuristics** (label length, Shannon entropy, query rate, NXDOMAIN ratio). *Implemented by the author as a guided exercise* | New detection class, learning on the author's side |
| 2.8 | Evaluate on public pcaps (e.g. Stratosphere IPS / CTU-13, Malware-Traffic-Analysis.net samples), respecting their licenses | External validity |

**Exit criteria:** real-capture scorecard published. TRW and the window
detector are compared on the same data. The passive-FTP false positive is
fixed or explained.

**Learning objectives:** sequential hypothesis testing (TRW), base-rate
fallacy, entropy, the DNS protocol, building a safe lab, writing an
evaluation methodology.

---

## Phase 3: Behavioural analytics & alert lifecycle ⏳

- C2 **beaconing** detection on flows: inter-arrival regularity (coefficient of variation, jitter tolerance), plus payload size consistency
- Data-exfiltration heuristics: outbound/inbound byte ratio, unusual volume per destination
- Rogue DHCP server and new-device detection
- Alert lifecycle: IDs, early-warning plus final incident, max incident age for live mode
- Optional persistence (SQLite) for long-running live sessions and baselines

**Learning objectives:** time-series features, the statistics of periodicity,
baselining, stateful stream processing.

---

## Phase 4: Reporting, UI and integrations ⏳

- Self-contained HTML report (timeline, top talkers, alert cards), suitable for portfolio screenshots
- Lightweight web dashboard for live mode
- Elastic Common Schema (ECS) output and a Filebeat/Vector example; Sigma-style rule descriptions
- Inputs: Zeek `conn.log`/`dns.log` and Suricata EVE JSON as alternative sources
- Docker image; `pipx install` support; signed release on GitHub

**Learning objectives:** SIEM data models, log pipelines, packaging and release
engineering.

---

## Phase 5: Advanced / research (optional) ⏳

- Unsupervised anomaly detection on flow features (e.g. Isolation Forest), evaluated honestly against the rule-based detectors
- TLS fingerprinting (JA4) for client identification
- Performance: profiling, multiprocessing by flow hash, or a Rust decoder via PyO3

---

## Changelog of this roadmap

- 2026-10-20: Phases 0–1 completed (v0.1.0). Phase 2 is next.
