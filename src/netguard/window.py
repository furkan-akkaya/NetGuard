"""Sliding-window distinct counting and burst ("incident") aggregation.

This is the algorithmic heart of the scan detectors. See
``docs/learning/01-scan-detection.md`` for the full explanation.

Complexity, per key:

* ``observe``: O(1) amortized. Each event is appended once and evicted once.
* ``distinct``: O(1) — it is ``len()`` of a hash map of item -> count.
* memory: O(events inside the window), capped by ``max_events``.

Why not a plain ``set`` per key? A set cannot *forget*: an item seen 10 minutes
ago would still count. Why not recount the deque on every packet? That is
O(window) per packet. The deque + counter pair gives exact distinct counts over
a time window at O(1) amortized cost.
"""

from __future__ import annotations

from collections import Counter, deque
from collections.abc import Hashable, Iterator
from dataclasses import dataclass, field
from typing import Generic, TypeVar

K = TypeVar("K", bound=Hashable)
T = TypeVar("T", bound=Hashable)


class SlidingDistinct(Generic[T]):
    """Exact number of distinct items observed in the last ``window`` seconds."""

    __slots__ = ("_counts", "_events", "max_events", "window")

    def __init__(self, window: float, max_events: int = 10_000) -> None:
        self.window = window
        self.max_events = max_events
        self._events: deque[tuple[float, T]] = deque()
        self._counts: Counter[T] = Counter()

    def add(self, ts: float, item: T) -> None:
        self._events.append((ts, item))
        self._counts[item] += 1
        # Memory bound: under a flood we forget the oldest events early. This may
        # *undercount* (a possible false negative) but can never exhaust RAM.
        if len(self._events) > self.max_events:
            self._pop_oldest()
        self.evict(ts)

    def evict(self, now: float) -> None:
        cutoff = now - self.window
        while self._events and self._events[0][0] < cutoff:
            self._pop_oldest()

    def _pop_oldest(self) -> None:
        _, old = self._events.popleft()
        self._counts[old] -= 1
        if self._counts[old] == 0:
            del self._counts[old]

    def distinct(self) -> int:
        return len(self._counts)

    def items(self) -> Iterator[T]:
        return iter(self._counts)

    def __len__(self) -> int:
        return len(self._events)

    @property
    def first_ts(self) -> float | None:
        return self._events[0][0] if self._events else None


@dataclass
class Incident(Generic[K, T]):
    """One continuous burst of suspicious activity for a key.

    An incident opens when the distinct count crosses the threshold and closes
    after ``idle_timeout`` seconds without new events. One incident becomes one
    alert, which is the main defence against alert floods: a 65 535-port scan is
    one alert with rich evidence, not 65 535 alerts.
    """

    key: K
    first_seen: float
    last_seen: float
    items: set[T] = field(default_factory=set)
    items_truncated: int = 0
    events: int = 0
    tags: Counter[str] = field(default_factory=Counter)
    responses: dict[str, set[Hashable]] = field(default_factory=dict)
    peak_distinct: int = 0
    max_items: int = 4096

    def add_item(self, item: T) -> None:
        if item in self.items:
            return
        if len(self.items) < self.max_items:
            self.items.add(item)
        else:
            self.items_truncated += 1

    def add_response(self, kind: str, value: Hashable) -> None:
        bucket = self.responses.setdefault(kind, set())
        if len(bucket) < self.max_items:
            bucket.add(value)

    @property
    def distinct_items(self) -> int:
        return len(self.items) + self.items_truncated

    @property
    def duration(self) -> float:
        return self.last_seen - self.first_seen


class BurstTracker(Generic[K, T]):
    """Per-key sliding windows that open :class:`Incident` objects on threshold."""

    def __init__(
        self,
        *,
        window: float,
        threshold: int,
        idle_timeout: float,
        max_keys: int = 100_000,
        max_events_per_key: int = 10_000,
    ) -> None:
        if threshold < 1:
            raise ValueError("threshold must be >= 1")
        self.window = window
        self.threshold = threshold
        self.idle_timeout = idle_timeout
        self.max_keys = max_keys
        self.max_events_per_key = max_events_per_key
        self._windows: dict[K, SlidingDistinct[T]] = {}
        self._incidents: dict[K, Incident[K, T]] = {}
        # Evidence gathered *before* the threshold is crossed (probe tags and
        # responses), merged into the incident when it opens. Without this the
        # SYN-ACK for the very first probed port would be lost.
        self._pending: dict[K, Incident[K, T]] = {}
        self.dropped_keys = 0  # observability: how often we hit the key cap

    def observe(self, key: K, ts: float, item: T, tag: str | None = None) -> Incident[K, T] | None:
        win = self._windows.get(key)
        if win is None:
            if len(self._windows) >= self.max_keys:
                self._gc(ts)
                if len(self._windows) >= self.max_keys:
                    self.dropped_keys += 1
                    return self._incidents.get(key)
            win = self._windows[key] = SlidingDistinct(self.window, self.max_events_per_key)
        win.add(ts, item)

        incident = self._incidents.get(key)
        if incident is None:
            pending = self._pending.setdefault(key, Incident(key=key, first_seen=ts, last_seen=ts))
            if tag:
                pending.tags[tag] += 1
            if win.distinct() < self.threshold:
                return None
            # Threshold crossed: promote the pending evidence to a real incident.
            incident = self._pending.pop(key)
            incident.first_seen = ts if win.first_ts is None else win.first_ts  # not `or`: 0.0 is falsy
            incident.events = len(win)
            for seen in win.items():
                incident.add_item(seen)
            self._incidents[key] = incident
        else:
            incident.events += 1
            incident.add_item(item)
            if tag:
                incident.tags[tag] += 1
        incident.last_seen = ts
        incident.peak_distinct = max(incident.peak_distinct, win.distinct())
        return incident

    def note_response(self, key: K, kind: str, value: Hashable) -> None:
        """Record a reply (e.g. SYN-ACK = open port) for a key that is being tracked."""
        target = self._incidents.get(key) or self._pending.get(key)
        if target is not None:
            target.add_response(kind, value)

    def incident(self, key: K) -> Incident[K, T] | None:
        return self._incidents.get(key)

    def window_of(self, key: K) -> SlidingDistinct[T] | None:
        return self._windows.get(key)

    def expire(self, now: float) -> list[Incident[K, T]]:
        """Close incidents idle for longer than ``idle_timeout``; GC empty windows."""
        closed = [inc for inc in self._incidents.values() if now - inc.last_seen > self.idle_timeout]
        for inc in closed:
            del self._incidents[inc.key]
        self._gc(now)
        return closed

    def drain(self) -> list[Incident[K, T]]:
        """Close every open incident (end of input)."""
        closed = list(self._incidents.values())
        self._incidents.clear()
        return closed

    def _gc(self, now: float) -> None:
        stale = []
        for key, win in self._windows.items():
            win.evict(now)
            if not len(win) and key not in self._incidents:
                stale.append(key)
        for key in stale:
            del self._windows[key]
            self._pending.pop(key, None)

    @property
    def tracked_keys(self) -> int:
        return len(self._windows)
