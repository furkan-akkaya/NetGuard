"""Complete observation time, not packet count, determines baseline eligibility."""

import pytest

from netguard.baseline import IntervalBaselines
from netguard.config import Config, ConnRateConfig, VolumeConfig
from netguard.engine import Engine, analyze_packets
from tests.helpers import udp


def baseline():
    return IntervalBaselines(interval=60, smoothing=0.1, warmup=2, sensitivity=6, min_value=50, max_entities=10)


@pytest.mark.parametrize("start", [0.001, 1.0, 30.0, 59.999, 120.001, 179.999])
def test_partial_start_never_trains_or_counts_toward_warmup(start):
    b = baseline()
    boundary = (start // 60 + 1) * 60
    b.add("h", start, 1)
    assert b.roll(boundary) == []
    assert "h" not in b._baselines
    for offset in (0, 60):
        b.add("h", boundary + offset, 10)
        b.roll(boundary + offset + 60)
    assert b._baselines["h"].n == 2
    assert b._baselines["h"].mean == 10
    b.add("h", boundary + 120, 500)
    assert b.roll(boundary + 180) == []
    (a,) = b.drain()
    assert a.baseline_intervals == 2
    assert a.baseline_mean == 10
    assert a.first_seen == boundary + 120
    assert a.last_seen == boundary + 180


@pytest.mark.parametrize("start", [0.0, 60.0, 120.0])
def test_exact_boundary_is_a_full_first_interval(start):
    b = baseline()
    b.add("h", start, 10)
    b.roll(start + 60)
    assert b._baselines["h"].n == 1
    assert b._baselines["h"].mean == 10


def test_partial_tail_does_not_score_learn_or_extend_an_open_anomaly():
    b = baseline()
    for t in (0, 60):
        b.add("h", t, 10)
    b.add("h", 120, 500)
    b.roll(180)
    mean, n = b._baselines["h"].mean, b._baselines["h"].n
    b.add("h", 181, 900)
    (a,) = b.drain()
    assert (a.total, a.intervals, a.last_seen) == (500, 1, 180)
    assert (b._baselines["h"].mean, b._baselines["h"].n) == (mean, n)
    assert b.drain() == []


def test_partial_tail_alone_cannot_raise_an_alarm():
    b = baseline()
    b.add("h", 0, 10)
    b.add("h", 60, 10)
    b.add("h", 120, 900)
    assert b.drain() == []
    assert b._baselines["h"].n == 2


def test_silent_full_intervals_after_partial_start_count_as_zero():
    b = baseline()
    b.add("h", 59, 1)
    b.add("h", 60, 100)
    b.roll(240)
    assert b._baselines["h"].n == 3
    assert b._baselines["h"].mean == pytest.approx(81)
    b.roll(100_000)  # bounded catch-up through a long silent gap
    assert b._baselines["h"].mean < 0.01


@pytest.mark.parametrize("start", [0.0, 0.01, 30.0, 59.99])
@pytest.mark.parametrize("complete_tail", [False, True])
def test_rate_and_volume_share_complete_interval_policy(start, complete_tail):
    cfg = Config(
        connrate=ConnRateConfig(warmup_intervals=2, min_count=50),
        volume=VolumeConfig(warmup_intervals=2, min_bytes=1000),
    )
    boundary = (start // 60 + 1) * 60
    pkts = [udp(start, "10.0.0.20", "10.0.0.10", 443, sport=9000)]
    for t, count in [(boundary, 5), (boundary + 60, 5), (boundary + 120, 100)]:
        pkts += [udp(t + k * 0.01, "10.0.0.20", "10.0.0.10", 443, sport=10000 + int(t) + k) for k in range(count)]
    engine = Engine(cfg)
    for pkt in pkts:
        engine.process(pkt)
    if complete_tail:
        engine.advance(boundary + 180)  # real elapsed silence, not an invented EOF interval
    result = engine.finish()
    rules = {a.rule_id for a in result.alerts} & {"NG-RATE-001", "NG-VOL-001"}
    assert rules == ({"NG-RATE-001", "NG-VOL-001"} if complete_tail else set())
    # The offline path agrees when an actual packet advances the capture clock.
    if complete_tail:
        pkts.append(udp(boundary + 180, "10.0.0.30", "10.0.0.10", 443))
        assert {a.rule_id for a in analyze_packets(pkts, cfg).alerts} & rules == rules
