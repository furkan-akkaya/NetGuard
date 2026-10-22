"""Abnormal traffic volume: a host sending far more bytes than it usually does.

Bulk exfiltration, a host joining a flood, or a compromised machine serving
data all appear as a jump in bytes *sent* by that host. Like the
connection-rate rule, each host is compared with its own EWMA baseline per
interval (see ``baseline.py``). Bytes are captured frame lengths, so a capture
with a short snaplen under-counts; the rule then fires later, never falsely.

Expected benign triggers: backups, software updates being served, large
uploads, a new video call. The alert says how unusual the volume is for this
host; deciding whether it is wanted needs context the network cannot provide.
"""

from __future__ import annotations

from collections.abc import Iterable

from netguard.baseline import Anomaly, IntervalBaselines
from netguard.config import Config
from netguard.detectors.base import Detector, RuleInfo
from netguard.models import Alert, Packet, Severity

RULE_ID = "NG-VOL-001"


def _mb(n: float) -> str:
    return f"{n / 1e6:,.1f} MB"


class VolumeDetector(Detector):
    name = "volume"
    rules = (RuleInfo(RULE_ID, "Abnormal outbound traffic volume"),)

    def __init__(self, config: Config) -> None:
        self.cfg = config.volume
        self.global_cfg = config
        self.baselines = IntervalBaselines(
            interval=self.cfg.interval_seconds,
            smoothing=self.cfg.smoothing,
            warmup=self.cfg.warmup_intervals,
            sensitivity=self.cfg.sensitivity,
            min_value=self.cfg.min_bytes,
            max_entities=self.cfg.max_sources,
        )

    def on_packet(self, pkt: Packet) -> Iterable[Alert]:
        if pkt.src_ip is None or self.global_cfg.is_allowlisted(pkt.src_ip):
            return ()
        return [self._alert(a) for a in self.baselines.add(pkt.src_ip, pkt.ts, pkt.length)]

    def tick(self, now: float) -> Iterable[Alert]:
        return [self._alert(a) for a in self.baselines.roll(now)]

    def flush(self) -> Iterable[Alert]:
        return [self._alert(a) for a in self.baselines.drain()]

    def _alert(self, a: Anomaly) -> Alert:
        factor = a.peak / a.baseline_mean if a.baseline_mean > 0 else None
        factor_text = f"{factor:.1f}x its baseline" if factor is not None else "far above its baseline"
        interval = self.cfg.interval_seconds
        rate = a.peak * 8 / interval / 1e6
        summary = (
            f"{a.entity} sent {_mb(a.peak)} in one {interval:g}s interval ({rate:,.1f} Mbit/s), {factor_text} "
            f"of {_mb(a.baseline_mean)} ± {_mb(a.baseline_dev)} learned over {a.baseline_intervals} intervals "
            f"(threshold {_mb(a.threshold)}: mean + {self.cfg.sensitivity:g} x deviation, and at least "
            f"{_mb(self.cfg.min_bytes)}). The burst lasted {a.intervals} interval(s), {_mb(a.total)} in total. "
            f"Possible causes: data exfiltration, participation in a flood, or a legitimate bulk transfer "
            f"(backup, update, upload)."
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
                "peak_bytes_per_interval": a.peak,
                "total_bytes": a.total,
                "peak_mbit_per_second": round(rate, 2),
                "anomalous_intervals": a.intervals,
                "baseline_mean_bytes": round(a.baseline_mean),
                "baseline_deviation_bytes": round(a.baseline_dev),
                "baseline_intervals": a.baseline_intervals,
                "factor_over_baseline": round(factor, 1) if factor is not None else None,
                "threshold": {
                    "bytes": round(a.threshold),
                    "interval_seconds": interval,
                    "sensitivity": self.cfg.sensitivity,
                    "min_bytes": self.cfg.min_bytes,
                    "warmup_intervals": self.cfg.warmup_intervals,
                },
            },
        )
