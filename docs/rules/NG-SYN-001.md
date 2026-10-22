# NG-SYN-001 — Possible TCP SYN flood

- **Detector:** `synflood` · **ATT&CK:** [T1499.001 Endpoint Denial of Service: OS Exhaustion Flood](https://attack.mitre.org/techniques/T1499/001/)
- **Confidence wording:** "possible". An overloaded or unreachable service produces the same signal.

## What it detects

Many new TCP connection attempts to one `ip:port` of which few complete the
handshake: `hping3 -S --flood [--rand-source]`, botnet SYN floods.

## Signal

Per target `(ip, port)` and fixed interval, from the flow table's connection
events: `attempt`, `answered` (SYN-ACK), `rejected` (RST) and `established`
(originator's ACK). An interval is suspicious when `attempts ≥ min_attempts`
and `established ≤ max_completion_ratio × attempts`. Consecutive suspicious
intervals form one incident, reported after `idle_timeout_seconds` without one.
A port scan spreads attempts over many ports and never concentrates on one key.

| Setting (`[synflood]`) | Default | Meaning |
|---|---:|---|
| `interval_seconds` | 10 | Evaluation interval |
| `min_attempts` | 500 | Attempts per interval to one target |
| `max_completion_ratio` | 0.2 | Completed share at or below which it is suspicious |
| `idle_timeout_seconds` | 30 | Report after this long without a suspicious interval |
| `high_severity_attempts` | 5000 | Attempts for HIGH severity |
| `max_targets`, `max_sources_per_target` | 10 000, 4096 | Memory bounds |

## Evidence

`target_port`, `attempts`, `answered`, `rejected`, `established`,
`completion_ratio`, `answer_ratio`, `suspicious_intervals`,
`peak_attempts_per_interval`, `attempts_per_second`, `distinct_sources`
(`distinct_sources_capped` when more than the cap), `single_attempt_sources`,
`top_sources`, `threshold`. Many distinct single-attempt sources suggest
spoofing; very few sources suggest a tool without source randomisation.

## Known false positives

- A **service outage** with many legitimate clients (no SYN-ACK, or SYN-ACKs
  lost): `answer_ratio` near 0 is called out in the summary.
- Asymmetric routing where the sensor sees client→server but not the
  client's ACKs (all handshakes look incomplete). Check `answer_ratio` and
  whether any connection to the target ever completes.

A legitimate **flash crowd** is not a false positive: those handshakes complete
(`flash_crowd` scenario).

## Known false negatives

Low-rate floods under `min_attempts`, floods spread over many ports, and
completed-handshake floods (connection exhaustion, slowloris): those need
different rules.
