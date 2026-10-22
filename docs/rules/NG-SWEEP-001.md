# NG-SWEEP-001 — Host discovery sweep

- **Detector:** `hostsweep` · **ATT&CK:** [T1018 Remote System Discovery](https://attack.mitre.org/techniques/T1018/)

## What it detects

One source probing many **hosts** (horizontal scan): ping sweeps, `nmap -sn`,
`arp-scan`, and single-port sweeps such as `nmap -p 445 10.0.0.0/24`.

## Signal

Distinct destination hosts per source in a sliding window. Probes are ICMP /
ICMPv6 echo requests, ARP requests, and TCP probes (as in NG-SCAN-001) towards
**private** addresses only when `tcp_private_only = true`: a browser opens
connections to dozens of public CDN hosts within seconds. Replies (echo reply,
ARP reply, SYN-ACK/RST) are recorded as *alive hosts*.

| Setting (`[hostsweep]`) | Default | Meaning |
|---|---:|---|
| `min_distinct_hosts` | 15 | Distinct hosts within the window that open an incident |
| `window_seconds` | 60 | Sliding window length |
| `idle_timeout_seconds` | 10 | Quiet time after which the incident is reported |
| `high_severity_hosts` | 100 | Distinct hosts for HIGH severity |
| `tcp_private_only` | true | Count TCP probes only towards private addresses |

## Evidence

`distinct_hosts`, `probes`, `methods` (e.g. `{"ICMP": 254, "ARP": 254}`),
`duration_seconds`, `alive_hosts`, `sample_targets`, `threshold`.

## Known false positives

- **Monitoring pollers** (Nagios/Zabbix/PRTG) pinging many hosts every cycle
  (`monitoring_poller`): indistinguishable by rate alone. Allowlist them;
  each poll cycle is one alert.
- Network management tools, DHCP servers doing conflict detection (ICMP),
  service discovery on large flat networks.

## Known false negatives

Slow sweeps under the window threshold; sweeps distributed across sources;
TCP sweeps of public address space when `tcp_private_only` is on; protocols
other than ICMP/ARP/TCP (e.g. UDP-based discovery).

## Tuning

Allowlist monitoring systems first. On large /16 networks consider a higher
`min_distinct_hosts`; on small labs a lower one.
