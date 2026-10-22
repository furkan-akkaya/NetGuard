"""Sliding-window distinct counting and burst ("incident") aggregation.

This is the algorithmic heart of the scan detectors. See
``docs/learning/01-scan-detection.md`` for the full explanation.

Complexity, per key:

* ``observe``: O(1) amortized. Each event is appended once and evicted once.
* ``distinct``: O(1) — it is ``len()`` of a hash map of item -> count.
* memory: O(events inside the window), capped by ``max_events``.

Across keys, :class:`BurstTracker` keeps windows in least-recently-observed
order, so garbage collection pops stale keys from the front and stops at the
first live one (amortized O(1) per key), and a full table evicts the oldest
key in O(1). An earlier version rescanned every window whenever the table was
full, which let a spoofed-source flood cost O(max_keys) per packet.

Why not a plain ``set`` per key? A set cannot *forget*: an item seen 10 minutes
ago would still count. Why not recount the events on every packet? That is
O(window) per packet. The event queue + counter pair gives exact distinct
counts over a time window at O(1) amortized cost.

The queue is a list with a moving head index rather than a ``deque``: CPython
allocates 760 bytes for even an empty deque, and under a spoofed-source flood
there is one window per source. Popping advances the head; the consumed prefix
is deleted once it is more than half the list, so each event is still moved at
most a constant number of times (amortized O(1)).
"""

from __future__ import annotations

from collections import Counter, OrderedDict
from collections.abc import Hashable, Iterator
from dataclasses import dataclass, field
from typing import Generic, TypeVar

K = TypeVar("K", bound=Hashable)
T = TypeVar("T", bound=Hashable)

_COMPACT_MIN = 32  # do not bother compacting tiny lists


class SlidingDistinct(Generic[T]):
    """Exact number of distinct items observed in the last ``window`` seconds."""

    __slots__ = ("_counts", "_events", "_head", "max_events", "window")

    def __init__(self, window: float, max_events: int = 10_000) -> None:
        self.window = window
        self.max_events = max_events
        self._events: list[tuple[float, T, str | None]] = []
        self._head = 0
        self._counts: dict[T, int] = {}

    def add(self, ts: float, item: T, tag: str | None = None) -> None:
        self._events.append((ts, item, tag))
        self._counts[item] = self._counts.get(item, 0) + 1
        # Memory bound: under a flood we forget the oldest events early. This may
        # *undercount* (a possible false negative) but can never exhaust RAM.
        if len(self) > self.max_events:
            self._pop_oldest()
        self.evict(ts)

    def evict(self, now: float) -> None:
        cutoff = now - self.window
        events = self._events
        while self._head < len(events) and events[self._head][0] < cutoff:
            self._pop_oldest()

    def _pop_oldest(self) -> None:
        _, old, _ = self._events[self._head]
        self._head += 1
        if self._counts[old] == 1:
            del self._counts[old]
        else:
            self._counts[old] -= 1
        if self._head == len(self._events):
            self._events.clear()
            self._head = 0
        elif self._head >= _COMPACT_MIN and self._head * 2 >= len(self._events):
            del self._events[: self._head]
            self._head = 0

    def distinct(self) -> int:
        return len(self._counts)

    def items(self) -> Iterator[T]:
        return iter(self._counts)

    def tags(self) -> Counter[str]:
        """How many in-window events carried each tag."""
        return Counter(tag for _, _, tag in self._events[self._head :] if tag is not None)

    def __len__(self) -> int:
        return len(self._events) - self._head

    @property
    def first_ts(self) -> float | None:
        return self._events[self._head][0] if len(self) else None


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
        # Least recently observed first: see the module docstring.
        self._windows: OrderedDict[K, SlidingDistinct[T]] = OrderedDict()
        self._incidents: dict[K, Incident[K, T]] = {}
        # Responses seen *before* the threshold is crossed, merged into the
        # incident when it opens; without this the SYN-ACK for the very first
        # probed port would be lost. Created only when a response arrives, so
        # one-packet keys (a spoofed flood) cost just their window. Pre-threshold
        # probe tags live in the window's events instead.
        self._pending: dict[K, Incident[K, T]] = {}
        self.evicted_keys = 0  # observability: how often the key cap forced an early eviction

    def observe(self, key: K, ts: float, item: T, tag: str | None = None) -> Incident[K, T] | None:
        win = self._windows.get(key)
        if win is None:
            if len(self._windows) >= self.max_keys:
                self._gc(ts)
                if len(self._windows) >= self.max_keys:
                    # Fail open, in O(1): forget the least recently active key.
                    # Its open incident (if any) survives; only pre-threshold
                    # state is lost, which can cause a false negative.
                    oldest, _ = self._windows.popitem(last=False)
                    self._pending.pop(oldest, None)
                    self.evicted_keys += 1
            win = self._windows[key] = SlidingDistinct(self.window, self.max_events_per_key)
        else:
            self._windows.move_to_end(key)
        win.add(ts, item, tag)

        incident = self._incidents.get(key)
        if incident is None:
            if win.distinct() < self.threshold:
                return None
            # Threshold crossed: open an incident from the window's evidence.
            incident = self._pending.pop(key, None) or Incident(key=key, first_seen=ts, last_seen=ts)
            incident.first_seen = ts if win.first_ts is None else win.first_ts  # not `or`: 0.0 is falsy
            incident.events = len(win)
            incident.tags.update(win.tags())
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
        target = self._incidents.get(key)
        if target is None and key in self._windows:
            target = self._pending.get(key)
            if target is None:
                target = self._pending[key] = Incident(key=key, first_seen=0.0, last_seen=0.0)
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
            # Each event belongs to at most one incident: start the key afresh,
            # otherwise the next probe would re-open an incident from events
            # that were already reported (overlapping, double-counted alerts).
            self._windows.pop(inc.key, None)
        self._gc(now)
        return closed

    def drain(self) -> list[Incident[K, T]]:
        """Close every open incident (end of input)."""
        closed = list(self._incidents.values())
        self._incidents.clear()
        return closed

    def _gc(self, now: float) -> None:
        """Drop keys whose window has emptied, oldest first, stopping at the first live key."""
        while self._windows:
            key, win = next(iter(self._windows.items()))
            win.evict(now)
            if len(win):
                break
            del self._windows[key]
            self._pending.pop(key, None)

    @property
    def tracked_keys(self) -> int:
        return len(self._windows)
