# NG-RATE-001 — Unusual connection frequency

- **Detector:** `connrate` · **ATT&CK:** none (an anomaly, not a specific technique; often co-occurs with T1046, T1110, T1210)

## What it detects

A host originating far more new connections (TCP and UDP flows) than its own
history predicts: worm-like spreading, brute force, scanning or a compromised
host starting a new activity.

## Signal

New flows originated per source per interval, compared with that source's
EWMA baseline (`netguard/baseline.py`): alert when, after `warmup_intervals`,
the count is ≥ `min_count` and > `mean + sensitivity × max(deviation, 0.25 ×
mean, 1)`. Anomalous intervals are learned clipped to the threshold, so an
attack does not instantly become normal; consecutive anomalous intervals are
one incident.

| Setting (`[connrate]`) | Default |
|---|---:|
| `interval_seconds` | 60 |
| `min_count` | 100 |
| `sensitivity` | 6 |
| `warmup_intervals` | 10 |
| `smoothing` (α) | 0.1 |
| `max_sources` | 10 000 |

## Evidence

`peak_connections_per_interval`, `mean_connections_per_interval`,
`total_connections`, `anomalous_intervals`, `baseline_mean`,
`baseline_deviation`, `baseline_intervals`, `factor_over_baseline`, `threshold`.

## Known false positives

New legitimate workloads (a build server starting a job, a backup, software
updates), a host that was idle during warm-up. Gradual growth is learned
(`growing_workload` scenario).

## Known false negatives

Captures shorter than the warm-up (default 10 minutes) can never alert; slow
activity that grows gradually; activity below `min_count`. Overlaps with the
scan rules by design; correlation groups related alerts into incidents.

## Observation boundaries (1.0.0rc2)

Only complete epoch-aligned intervals train and score. Discard the partial first interval and unfinished EOF tail. Silent complete intervals count as zero. Warm-up counts complete intervals only. See [boundary decision](../BASELINE_INTERVALS.md). Fixed-window splitting and activity in the partial tail can still be missed.
