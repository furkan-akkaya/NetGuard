# NG-VOL-001 — Abnormal outbound traffic volume

- **Detector:** `volume` · **ATT&CK:** none (an anomaly; may indicate T1048 exfiltration, or a host participating in a flood)

## What it detects

A host sending far more bytes than its own history predicts.

## Signal

Captured bytes sent per source IP per interval against the source's EWMA
baseline (same algorithm as NG-RATE-001): alert when, after warm-up, the
volume is ≥ `min_bytes` and above `mean + sensitivity × max(deviation, 0.25 ×
mean, 1)`.

| Setting (`[volume]`) | Default |
|---|---:|
| `interval_seconds` | 60 |
| `min_bytes` | 20 000 000 |
| `sensitivity` | 6 |
| `warmup_intervals` | 10 |
| `smoothing` (α) | 0.1 |
| `max_sources` | 10 000 |

## Evidence

`peak_bytes_per_interval`, `total_bytes`, `peak_mbit_per_second`,
`anomalous_intervals`, `baseline_mean_bytes`, `baseline_deviation_bytes`,
`baseline_intervals`, `factor_over_baseline`, `threshold`.

## Known false positives

Backups, large uploads, software being served, video calls starting. The rule
says how unusual the volume is for this host; whether it is wanted needs
business context.

## Known false negatives

Low-and-slow exfiltration below `min_bytes` or within normal variance; short
captures (warm-up); bytes are captured lengths, so a short snaplen
under-counts (later detection, never false).
