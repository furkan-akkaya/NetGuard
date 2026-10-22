# NG-SCAN-003 — UDP port scan

- **Detector:** `udpscan` · **ATT&CK:** [T1046 Network Service Discovery](https://attack.mitre.org/techniques/T1046/)

## What it detects

One source sending UDP datagrams to many ports of one target (`nmap -sU`,
`unicornscan -mU`).

## Signal

A probe is the first datagram of a new UDP flow from its originator, so a DNS
server *answering* clients on many ephemeral ports is never counted. Distinct
destination ports per `(source, target)` in a sliding window open an incident.
Target reactions are recorded per port:

| Reaction | Port state |
|---|---|
| UDP reply from the probed port | open |
| ICMP port unreachable (3/3) quoting the probe | closed |
| other ICMP unreachable (admin prohibited, …) | filtered |
| nothing | open or filtered (silent) |

An incident in which more than `max_answered_ratio` of the ports answered is
not reported: that is a busy client (VoIP, games), not a scan.

| Setting (`[udpscan]`) | Default | Meaning |
|---|---:|---|
| `min_distinct_ports` | 15 | Distinct ports within the window |
| `window_seconds` | 60 | Sliding window |
| `idle_timeout_seconds` | 10 | Report after this much quiet |
| `high_severity_ports` | 100 | Ports for HIGH severity |
| `max_answered_ratio` | 0.5 | Suppress if more ports than this answered |

## Evidence

`distinct_ports`, `probes`, `duration_seconds`, `open_ports`,
`closed_ports_count`, `filtered_ports_count`, `silent_ports_count`,
`sample_ports`, `threshold`.

## Known false positives

Applications that send to many UDP ports of one host without getting replies:
some service-discovery protocols, broken media sessions.

## Known false negatives

Slow UDP scans under the window threshold. Linux rate-limits ICMP errors
(≈ 1/s), so closed ports usually look silent; the rule does not depend on
ICMP replies, they only enrich the evidence.
