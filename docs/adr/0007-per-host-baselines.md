# ADR-0007: Per-host EWMA baselines for rate and volume anomalies

- **Status:** Accepted
- **Date:** 2026-10-22

## Context

"Unusual connection frequency" and "abnormal traffic volume" have no
universal threshold: 2 000 new connections a minute is normal for a proxy and
alarming for a laptop. A global threshold is either noisy or blind.

## Decision

`netguard/baseline.py` keeps, per entity (source IP), an exponentially
weighted moving average of the per-interval value and of its absolute
deviation (α = 0.1, about 10 intervals of memory). After `warmup` intervals an
interval is anomalous when `x ≥ min_value` and
`x > mean + sensitivity · max(deviation, 0.25 · mean, 1)`. Anomalous values
are learned *clipped* to the threshold. Silent intervals count as zero.
Consecutive anomalous intervals form one incident. Two rules use it:
NG-RATE-001 (connection attempts originated) and NG-VOL-001 (bytes sent).

## Alternatives considered

| Option | Why not (now) |
|---|---|
| Global static thresholds | Wrong for most hosts at once |
| Mean/standard deviation over a sliding window | O(window) memory per host; the variance is dominated by the spikes we want to find |
| Median/MAD over a window | Robust, but needs the window's values per host (memory) |
| Seasonal models (Holt-Winters, time of day) | Need days of history; worth it once Phase 4 stores history |
| Isolation forest / ML | No labelled data to validate it; not explainable enough for the alert text (roadmap: ML only with a measured use case) |

EWMA + absolute deviation is O(1) memory and time per host and interval, and
its output explains itself ("47× its baseline of 9.2 ± 1.6").

## Consequences

- Offline captures shorter than the warm-up (10 minutes by default) cannot
  produce these alerts. This is reported, not hidden.
- Clipping prevents instant baseline poisoning but a permanent change is
  learned within a few intervals; a slow attacker who ramps up gradually is not
  detected (`growing_workload` demonstrates the benign side of that).
- Cost is O(tracked hosts) once per interval, never per packet, with at most
  `max_sources` hosts (LRU).
