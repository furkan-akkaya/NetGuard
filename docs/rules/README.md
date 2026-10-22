# Rule catalog

Every alert carries a stable `rule_id`. Each rule has one page here describing
what it detects, the exact signal and thresholds, the evidence it emits, known
false positives, tuning advice and its ATT&CK mapping. A `rule_id` never
changes meaning; a rule whose logic changes incompatibly gets a new id.

| Rule | Detector | Title | ATT&CK | Default severity |
|---|---|---|---|---|
| [NG-SCAN-001](NG-SCAN-001.md) | `portscan` | TCP port scan | T1046 | MEDIUM, HIGH ≥ 100 ports |
| [NG-SWEEP-001](NG-SWEEP-001.md) | `hostsweep` | Host discovery sweep | T1018 | MEDIUM, HIGH ≥ 100 hosts |
| [NG-ARP-001](NG-ARP-001.md) | `arpspoof` | ARP binding change (possible ARP spoofing) | T1557.002 | MEDIUM, HIGH for critical IPs or flip-flops |

Alert JSON contract: `schema_version` "1.0" (see [ARCHITECTURE.md](../ARCHITECTURE.md#data-model)).
`alert_id` is a deterministic hash of `rule_id`, `src`, `dst` and `first_seen`,
so re-analysing the same capture yields the same ids.
