# NG-SCAN-001 — TCP port scan

- **Detector:** `portscan` · **ATT&CK:** [T1046 Network Service Discovery](https://attack.mitre.org/techniques/T1046/)
- **Confidence wording:** "probed N distinct ports". The rule observes probing behaviour; it does not prove intent.

## What it detects

One source sending connection probes to many TCP ports of **one** target
(vertical scan): `nmap -sS/-sT/-sN/-sF/-sX`, `masscan` against a single host.

## Signal

A *probe* is a TCP segment without ACK that opens or pokes a connection:
`SYN` (connect/half-open), no flags (NULL), `FIN`, or `FIN|PSH|URG` (XMAS).
The detector counts **distinct destination ports per (source, target)** in a
sliding window. Crossing the threshold opens an incident that keeps collecting
evidence and is reported once, after it has been idle (ADR-0003).

| Setting (`[portscan]`) | Default | Meaning |
|---|---:|---|
| `min_distinct_ports` | 15 | Distinct ports within the window that open an incident |
| `window_seconds` | 60 | Sliding window length |
| `idle_timeout_seconds` | 10 | Quiet time after which the incident is reported |
| `high_severity_ports` | 100 | Distinct ports for HIGH severity |

Sources in the global `allowlist` are ignored.

## Evidence

`distinct_ports`, `probes`, `probe_types` (e.g. `{"SYN": 1000}`),
`duration_seconds`, `probes_per_second`, `open_ports` (answered SYN-ACK),
`closed_ports_count` (answered RST), `unanswered_ports_count`,
`sample_ports`, `threshold`. Non-SYN probe types are called out as a deliberate
stealth scan in the summary.

## Known false positives

- **Passive-mode FTP and some P2P clients** open many successful connections to
  changing ports (synthetic scenario `passive_ftp`). The rule counts probes
  without looking at whether connections succeed. Phase 3 (TRW) uses the flow
  states from Phase 2 (`SF` vs `S0/REJ`) to fix this.
- **Vulnerability scanners and monitoring** — expected; allowlist them.

## Known false negatives

- Slow scans that stay below the threshold in every window (`slow_scan`, `nmap -T1`).
- Distributed or decoy scans (`nmap -D`): probes are split across many sources.
- UDP scans (`nmap -sU`) — not covered by this rule.
- Fragmented probes (`nmap -f`): non-first fragments have no TCP header.

## Tuning

Lower `min_distinct_ports` for sensitive segments (servers rarely receive
connections to >10 ports from one client); raise it on networks with heavy
legitimate multi-port clients. Prefer allowlisting known scanners over raising
thresholds globally.
