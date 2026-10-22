"""Per-entity behavioural baselines over fixed intervals (EWMA mean and deviation).

Some anomalies are only anomalous *for that host*: 2 000 new connections a
minute is normal for a proxy and alarming for a workstation. A per-host
baseline answers "is this unusual for this host?" instead of applying one
global threshold.

For each entity and fixed interval (``interval`` seconds of capture time) we
sum a value (connection attempts, bytes sent). When an interval ends, each
entity's value ``x`` is compared with its baseline, then folded into it::

    deviation = (1 - alpha) · deviation + alpha · |x - mean|
    mean      = mean + alpha · (x - mean)

This is an exponentially weighted moving average of the value and of its
absolute deviation; ``alpha = smoothing`` sets the memory (≈ 1/alpha intervals). The
absolute deviation is less dominated by single spikes than a variance would
be. An interval is anomalous when, after ``warmup`` intervals of history::

    x >= min_value   and   x > mean + sensitivity · max(deviation, 0.25 · mean, 1)

The floor stops a perfectly regular host (deviation ≈ 0) from alerting on any
increase at all. Anomalous values are folded in *clipped* to the threshold, so
an attack does not instantly become the new normal (baseline poisoning), while
a permanent change is still learned over a few intervals. Consecutive
anomalous intervals form one incident.

Intervals in which an entity is silent count as zero. Cost: O(tracked
entities) once per interval, never per packet; at most ``max_entities`` are
tracked (least recently active evicted). Offline captures shorter than
``warmup`` intervals can never alert, which is reported as a limitation.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass

_MAX_EMPTY_INTERVALS = 100  # beyond this many silent intervals the baseline has decayed anyway
_REL_FLOOR = 0.25


@dataclass(slots=True)
class Ewma:
    mean: float = 0.0
    dev: float = 0.0
    n: int = 0

    def threshold(self, sensitivity: float) -> float:
        return self.mean + sensitivity * max(self.dev, _REL_FLOOR * self.mean, 1.0)

    def update(self, x: float, alpha: float) -> None:
        if self.n == 0:
            self.mean = x
        else:
            self.dev = (1 - alpha) * self.dev + alpha * abs(x - self.mean)
            self.mean += alpha * (x - self.mean)
        self.n += 1


@dataclass
class Anomaly:
    entity: str
    first_seen: float
    last_seen: float
    intervals: int
    total: float
    peak: float
    baseline_mean: float  # baseline when the anomaly started
    baseline_dev: float
    baseline_intervals: int
    threshold: float


class IntervalBaselines:
    def __init__(
        self,
        *,
        interval: float,
        smoothing: float,
        warmup: int,
        sensitivity: float,
        min_value: float,
        max_entities: int,
    ) -> None:
        self.interval = interval
        self.alpha = smoothing
        self.warmup = warmup
        self.sensitivity = sensitivity
        self.min_value = min_value
        self.max_entities = max_entities
        self._slot: float | None = None
        self._current: dict[str, float] = {}
        self._baselines: OrderedDict[str, Ewma] = OrderedDict()  # least recently active first
        self._open: dict[str, Anomaly] = {}
        self.evicted = 0

    def add(self, entity: str, ts: float, amount: float) -> list[Anomaly]:
        ended = self.roll(ts)
        self._current[entity] = self._current.get(entity, 0.0) + amount
        return ended

    def roll(self, now: float) -> list[Anomaly]:
        """Close every interval that ended before ``now``; return anomalies that ended."""
        if self._slot is None:
            self._slot = (now // self.interval) * self.interval
            return []
        ended: list[Anomaly] = []
        closed = 0
        while now >= self._slot + self.interval:
            # The first closed interval holds the data; later ones are silent (all zero).
            ended += self._close_interval()
            self._slot += self.interval
            closed += 1
            if closed >= _MAX_EMPTY_INTERVALS:
                self._slot = (now // self.interval) * self.interval  # skip the rest of a long gap
                break
        return ended

    def _close_interval(self) -> list[Anomaly]:
        assert self._slot is not None
        start, end = self._slot, self._slot + self.interval
        current, self._current = self._current, {}
        for entity in current:
            if entity in self._baselines:
                self._baselines.move_to_end(entity)
            else:
                if len(self._baselines) >= self.max_entities:
                    old, _ = self._baselines.popitem(last=False)
                    self._open.pop(old, None)
                    self.evicted += 1
                self._baselines[entity] = Ewma()
        ended: list[Anomaly] = []
        for entity, base in self._baselines.items():
            x = current.get(entity, 0.0)
            limit = base.threshold(self.sensitivity)
            if base.n >= self.warmup and x >= self.min_value and x > limit:
                anomaly = self._open.get(entity)
                if anomaly is None:
                    anomaly = self._open[entity] = Anomaly(
                        entity, start, end, 0, 0.0, 0.0, base.mean, base.dev, base.n, limit
                    )
                anomaly.last_seen = end
                anomaly.intervals += 1
                anomaly.total += x
                anomaly.peak = max(anomaly.peak, x)
                base.update(limit, self.alpha)  # clipped: do not learn the attack at full strength
            else:
                if entity in self._open:
                    ended.append(self._open.pop(entity))
                base.update(x, self.alpha)
        return ended

    def drain(self) -> list[Anomaly]:
        """End of input: close the current interval and every open anomaly."""
        ended = self._close_interval() if self._slot is not None and self._current else []
        ended += self._open.values()
        self._open.clear()
        return ended
