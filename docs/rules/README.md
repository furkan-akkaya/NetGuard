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
| [NG-SCAN-002](NG-SCAN-002.md) | `trw` | Scan detected by connection outcomes (TRW) | T1046 | MEDIUM, HIGH ≥ 100 failures |
| [NG-SCAN-003](NG-SCAN-003.md) | `udpscan` | UDP port scan | T1046 | MEDIUM, HIGH ≥ 100 ports |
| [NG-SYN-001](NG-SYN-001.md) | `synflood` | Possible TCP SYN flood | T1499.001 | MEDIUM, HIGH ≥ 5000 attempts |
| [NG-DNS-001](NG-DNS-001.md) | `dnstunnel` | Possible DNS tunnelling | T1071.004 | MEDIUM, HIGH ≥ 500 subdomains or mostly TXT/NULL |
| [NG-DNS-002](NG-DNS-002.md) | `nxdomain` | Burst of failed DNS lookups (possible DGA) | T1568.002 | MEDIUM, HIGH ≥ 200 names |
| [NG-FRAG-001](NG-FRAG-001.md) | `fragments` | Suspicious IP fragmentation (possible IDS evasion) | T1599 | MEDIUM, HIGH ≥ 100 fragments |
| [NG-RATE-001](NG-RATE-001.md) | `connrate` | Unusual connection frequency | — | MEDIUM, HIGH ≥ 20× baseline |
| [NG-VOL-001](NG-VOL-001.md) | `volume` | Abnormal outbound traffic volume | — | MEDIUM, HIGH ≥ 20× baseline |

`netguard rules` prints this list with the state (on/off) from your configuration.

Every alert also carries an explainable confidence score and alerts are
grouped into incidents: see [CONFIDENCE.md](../CONFIDENCE.md).

Alert JSON contract: `schema_version` "1.2" (see [ARCHITECTURE.md](../ARCHITECTURE.md#data-model)).
In live mode a rule can emit an `early` alert when an incident opens and a
`final` one when it closes, with the same `alert_id`.
`alert_id` is a deterministic hash of `rule_id`, `src`, `dst` and `first_seen`,
so re-analysing the same capture yields the same ids.
