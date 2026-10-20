import pytest

from netguard.window import BurstTracker, SlidingDistinct


def test_sliding_distinct_counts_unique_items():
    w: SlidingDistinct[int] = SlidingDistinct(window=10)
    for port in (22, 80, 22, 443, 80):
        w.add(0.0, port)
    assert w.distinct() == 3
    assert len(w) == 5


def test_sliding_distinct_forgets_old_events():
    w: SlidingDistinct[int] = SlidingDistinct(window=10)
    w.add(0.0, 1)
    w.add(5.0, 2)
    w.add(10.0, 3)
    assert w.distinct() == 3  # event at t=0 is exactly on the boundary: kept
    w.add(10.5, 3)
    assert set(w.items()) == {2, 3}


def test_sliding_distinct_is_memory_bounded():
    w: SlidingDistinct[int] = SlidingDistinct(window=1000, max_events=100)
    for i in range(1000):
        w.add(0.0, i)
    assert len(w) == 100
    assert w.distinct() == 100


def test_burst_tracker_opens_incident_on_threshold():
    t: BurstTracker[str, int] = BurstTracker(window=60, threshold=3, idle_timeout=5)
    assert t.observe("a", 0.0, 1, "SYN") is None
    assert t.observe("a", 0.1, 2, "SYN") is None
    inc = t.observe("a", 0.2, 3, "FIN")
    assert inc is not None
    assert inc.items == {1, 2, 3}
    assert inc.events == 3
    assert inc.tags == {"SYN": 2, "FIN": 1}  # pre-threshold tags are kept
    assert inc.first_seen == 0.0


def test_burst_tracker_keeps_responses_seen_before_threshold():
    t: BurstTracker[str, int] = BurstTracker(window=60, threshold=2, idle_timeout=5)
    t.observe("a", 0.0, 22)
    t.note_response("a", "open", 22)  # SYN-ACK arrives before the 2nd probe
    inc = t.observe("a", 0.1, 23)
    assert inc is not None
    assert inc.responses["open"] == {22}


def test_burst_tracker_ignores_responses_for_unknown_keys():
    t: BurstTracker[str, int] = BurstTracker(window=60, threshold=2, idle_timeout=5)
    t.note_response("nobody", "open", 22)
    assert t.incident("nobody") is None


def test_incident_closes_after_idle_timeout():
    t: BurstTracker[str, int] = BurstTracker(window=60, threshold=2, idle_timeout=5)
    t.observe("a", 0.0, 1)
    t.observe("a", 1.0, 2)
    assert t.expire(5.0) == []
    closed = t.expire(6.5)
    assert [i.key for i in closed] == ["a"]
    assert t.incident("a") is None


def test_drain_returns_open_incidents():
    t: BurstTracker[str, int] = BurstTracker(window=60, threshold=1, idle_timeout=5)
    t.observe("a", 0.0, 1)
    t.observe("b", 0.0, 1)
    assert sorted(i.key for i in t.drain()) == ["a", "b"]
    assert t.drain() == []


def test_key_limit_drops_new_keys_instead_of_growing():
    t: BurstTracker[str, int] = BurstTracker(window=60, threshold=5, idle_timeout=5, max_keys=2)
    t.observe("a", 0.0, 1)
    t.observe("b", 0.0, 1)
    t.observe("c", 0.0, 1)
    assert t.tracked_keys == 2
    assert t.dropped_keys == 1


def test_gc_frees_idle_keys_when_limit_is_hit():
    t: BurstTracker[str, int] = BurstTracker(window=10, threshold=5, idle_timeout=5, max_keys=1)
    t.observe("a", 0.0, 1)
    t.observe("b", 100.0, 1)  # "a" has no events in the window any more
    assert t.dropped_keys == 0
    assert t.window_of("a") is None


def test_threshold_must_be_positive():
    with pytest.raises(ValueError, match="threshold"):
        BurstTracker(window=1, threshold=0, idle_timeout=1)
