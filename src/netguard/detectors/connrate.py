"""Unusual connection frequency: a host opening far more new connections than it usually does.

Worm propagation, scanning from a compromised host, brute-force tools and
some malware loaders all show up as a sudden jump in the number of new
connections a host *originates*. What is "a lot" depends on the host, so the
detector compares each source with its own EWMA baseline (see
``baseline.py``): new TCP and UDP flows originated per interval.

This rule overlaps with the scan rules by design; it also catches activity the
scan rules do not model (e.g. many successful connections to many services).
Correlating the overlapping alerts is Phase 7 work.
"""

from __future__ import annotations

from collections.abc import Iterable

from netguard.baseline import Anomaly, IntervalBaselines
from netguard.config import Config
from netguard.detectors.base import Detector, RuleInfo, as_early
from netguard.flows import ATTEMPT, Flow
from netguard.models import Alert, Severity

RULE_ID = "NG-RATE-001"


class ConnRateDetector(Detector):
    name = "connrate"
    rules = (RuleInfo(RULE_ID, "Unusual connection frequency"),)

    def __init__(self, config: Config) -> None:
        self.cfg = config.connrate
        self.global_cfg = config
        self.baselines = IntervalBaselines(
            interval=self.cfg.interval_seconds,
            smoothing=self.cfg.smoothing,
            warmup=self.cfg.warmup_intervals,
            sensitivity=self.cfg.sensitivity,
            min_value=self.cfg.min_count,
            max_entities=self.cfg.max_sources,
            max_age=config.alerts.max_incident_age_seconds,
            track_opened=config.alerts.early_warning,
        )

    def on_conn_event(self, event: str, flow: Flow, ts: float) -> Iterable[Alert]:
        if event != ATTEMPT or self.global_cfg.is_allowlisted(flow.src_ip):
            return ()
        return [self._alert(a) for a in self.baselines.add(flow.src_ip, ts, 1)]

    def tick(self, now: float) -> Iterable[Alert]:
        ended = [self._alert(a) for a in self.baselines.roll(now)]
        return as_early(self._alert(a) for a in self.baselines.take_opened()) + ended

    def flush(self) -> Iterable[Alert]:
        return [self._alert(a) for a in self.baselines.drain()]

    def _alert(self, a: Anomaly) -> Alert:
        per_interval = a.total / a.intervals
        factor = a.peak / a.baseline_mean if a.baseline_mean > 0 else None
        factor_text = f"{factor:.1f}x its baseline" if factor is not None else "far above its baseline"
        interval = self.cfg.interval_seconds
        summary = (
            f"{a.entity} originated {a.peak:,.0f} new connections (TCP and UDP) in one {interval:g}s interval, "
            f"{factor_text} of {a.baseline_mean:.1f} ± {a.baseline_dev:.1f} learned over {a.baseline_intervals} "
            f"intervals (threshold {a.threshold:.0f}: mean + {self.cfg.sensitivity:g} x deviation, and at least "
            f"{self.cfg.min_count}). The burst lasted {a.intervals} interval(s), {a.total:,.0f} connections in "
            f"total. Possible causes: scanning, worm-like spreading or brute force from this host, or a new "
            f"legitimate workload."
        )
        return Alert(
            detector=self.name,
            rule_id=RULE_ID,
            title=self.rules[0].title,
            severity=Severity.HIGH if factor is not None and factor >= 20 else Severity.MEDIUM,
            first_seen=a.first_seen,
            last_seen=a.last_seen,
            src=a.entity,
            summary=summary,
            evidence={
                "peak_connections_per_interval": a.peak,
                "mean_connections_per_interval": round(per_interval, 1),
                "total_connections": a.total,
                "anomalous_intervals": a.intervals,
                "baseline_mean": round(a.baseline_mean, 2),
                "baseline_deviation": round(a.baseline_dev, 2),
                "baseline_intervals": a.baseline_intervals,
                "factor_over_baseline": round(factor, 1) if factor is not None else None,
                "threshold": {
                    "value": round(a.threshold, 1),
                    "interval_seconds": interval,
                    "sensitivity": self.cfg.sensitivity,
                    "min_count": self.cfg.min_count,
                    "warmup_intervals": self.cfg.warmup_intervals,
                },
            },
        )
