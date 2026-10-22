"""Unit tests for the Phase 3 detectors, driven through the engine with hand-built packets."""

import math
from collections.abc import Sequence

import pytest

from netguard.baseline import Anomaly, Ewma, IntervalBaselines
from netguard.config import Config, ConnRateConfig, SynFloodConfig, TrwConfig
from netguard.decode import decode
from netguard.detectors.fragments import FragmentDetector
from netguard.detectors.trw import TrwDetector
from netguard.dns import DnsInfo
from netguard.engine import Engine, analyze_packets
from netguard.models import ACK, RST, SYN, Alert, Packet

from .helpers import tcp, udp

SCANNER, TARGET = "10.0.0.66", "10.0.0.10"


def _only(alerts: list[Alert], detector: str) -> list[Alert]:
    return [a for a in alerts if a.detector == detector]


def _probe(ts: float, port: int, outcome: str | None, src: str = SCANNER, dst: str = TARGET) -> list[Packet]:
    """One TCP first contact and its outcome: 'open', 'closed' or None (no reply)."""
    sport = 40000 + port % 20000
    pkts = [tcp(ts, src, dst, port, SYN, sport=sport, seq=1)]
    if outcome == "open":
        pkts.append(tcp(ts + 0.001, dst, src, sport, SYN | ACK, sport=port, seq=9))
    elif outcome == "closed":
        pkts.append(tcp(ts + 0.001, dst, src, sport, RST | ACK, sport=port))
    return pkts


# --- TRW ----------------------------------------------------------------------


def test_trw_step_sizes_follow_the_paper():
    det = TrwDetector(Config())
    assert det.step_failure == pytest.approx(math.log(4))
    assert det.step_success == pytest.approx(-math.log(4))
    assert det.upper == pytest.approx(math.log(99))


def test_trw_needs_min_failures_even_after_the_test_decides():
    cfg = Config(trw=TrwConfig(min_failures=6))
    five = [p for i in range(5) for p in _probe(i, 1000 + i, "closed")]
    assert _only(analyze_packets(five, cfg).alerts, "trw") == []
    six = [p for i in range(6) for p in _probe(i, 1000 + i, "closed")]
    (alert,) = _only(analyze_packets(six, cfg).alerts, "trw")
    assert alert.evidence["decided_after_outcomes"] == 6


def test_trw_successes_pull_back_to_benign():
    pkts = []
    for i in range(30):  # alternating success and failure: 50% success is not scanner-like enough
        pkts += _probe(i, 2000 + i, "open" if i % 2 else "closed")
    assert _only(analyze_packets(pkts).alerts, "trw") == []


def test_trw_counts_each_target_once():
    pkts = [p for i in range(20) for p in _probe(i, 22, "closed")]  # the same port twenty times
    assert _only(analyze_packets(pkts).alerts, "trw") == []


def test_trw_unanswered_counts_only_after_handshake_timeout():
    pkts = [p for i in range(10) for p in _probe(i * 0.1, 3000 + i, None)]
    # Input ends before the 30 s handshake timeout: outcomes unknown, no verdict.
    assert _only(analyze_packets(pkts).alerts, "trw") == []
    # A later packet lets the flows time out as unanswered (S0): now they are failures.
    late = Packet(ts=100.0, length=60, proto="other")
    (alert,) = _only(analyze_packets([*pkts, late]).alerts, "trw")
    assert alert.evidence["unanswered"] == 10


def test_trw_respects_allowlist():
    pkts = [p for i in range(20) for p in _probe(i, 1000 + i, "closed")]
    assert _only(analyze_packets(pkts, Config(allowlist=[SCANNER])).alerts, "trw") == []


# --- SYN flood ------------------------------------------------------------------


def _syn_burst(n: int, start: float, complete: bool, step: float = 0.001) -> list[Packet]:
    pkts = []
    for i in range(n):
        src = f"198.18.{i // 250}.{i % 250 + 1}"
        ts = start + i * step
        pkts.append(tcp(ts, src, TARGET, 80, SYN, sport=5000, seq=1))
        pkts.append(tcp(ts + 0.0001, TARGET, src, 5000, SYN | ACK, sport=80, seq=1))
        if complete:
            pkts.append(tcp(ts + 0.0002, src, TARGET, 80, ACK, sport=5000, seq=2))
    return pkts


def test_synflood_alerts_on_incomplete_handshakes():
    (alert,) = _only(analyze_packets(_syn_burst(800, 0.0, complete=False)).alerts, "synflood")
    assert alert.dst == TARGET
    assert alert.evidence["attempts"] == 800
    assert alert.evidence["established"] == 0
    assert alert.evidence["answer_ratio"] == 1.0


def test_synflood_quiet_when_handshakes_complete():
    assert _only(analyze_packets(_syn_burst(800, 0.0, complete=True)).alerts, "synflood") == []


def test_synflood_below_rate_is_quiet():
    pkts = _syn_burst(400, 0.0, complete=False)  # 400 < 500 per 10 s
    assert _only(analyze_packets(pkts).alerts, "synflood") == []


def test_synflood_consecutive_intervals_form_one_incident():
    cfg = Config(synflood=SynFloodConfig(min_attempts=100))
    pkts = _syn_burst(1000, 0.0, complete=False, step=0.03)  # 30 s at ~33/s: three 10 s intervals
    pkts.append(Packet(ts=200.0, length=60, proto="other"))
    (alert,) = _only(analyze_packets(pkts, cfg).alerts, "synflood")
    assert alert.evidence["suspicious_intervals"] >= 3


def test_synflood_target_table_is_bounded():
    cfg = Config(synflood=SynFloodConfig(max_targets=10))
    engine = Engine(cfg)
    for port in range(100):
        engine.process(tcp(port * 0.01, SCANNER, TARGET, port + 1, SYN, sport=4000))
    det = next(d for d in engine.detectors if d.name == "synflood")
    assert len(det._intervals) <= 10  # type: ignore[attr-defined]
    assert det.evicted_targets == 90  # type: ignore[attr-defined]


# --- UDP scan -------------------------------------------------------------------


def test_dns_server_answering_many_ports_is_not_a_udp_scan():
    resolver, client = "10.0.0.53", "10.0.0.20"
    pkts = []
    for i in range(100):  # client queries from 100 ephemeral ports; the server answers each
        pkts.append(udp(i * 0.1, client, resolver, 53, sport=50000 + i))
        pkts.append(udp(i * 0.1 + 0.01, resolver, client, 50000 + i, sport=53))
    assert _only(analyze_packets(pkts).alerts, "udpscan") == []


def test_udp_scan_with_mostly_answered_ports_is_suppressed():
    pkts = []
    for port in range(1, 41):
        pkts.append(udp(port * 0.01, SCANNER, TARGET, port, sport=6000))
        if port <= 30:
            pkts.append(udp(port * 0.01 + 0.001, TARGET, SCANNER, 6000, sport=port))
    assert _only(analyze_packets(pkts).alerts, "udpscan") == []


# --- DNS ------------------------------------------------------------------------


def _dns_query(ts: float, name: str, qtype: int = 1, src: str = "10.0.0.20") -> Packet:
    info = DnsInfo(id=1, response=False, opcode=0, rcode=0, qdcount=1, ancount=0, qname=name, qtype=qtype)
    return Packet(ts=ts, length=80, proto="udp", src_ip=src, dst_ip="10.0.0.53", src_port=5000, dst_port=53, dns=info)


def _nx(ts: float, name: str, client: str = "10.0.0.20") -> Packet:
    info = DnsInfo(id=1, response=True, opcode=0, rcode=3, qdcount=1, ancount=0, qname=name, qtype=1)
    return Packet(
        ts=ts, length=80, proto="udp", src_ip="10.0.0.53", dst_ip=client, src_port=53, dst_port=5000, dns=info
    )


def test_dnstunnel_ignores_many_short_subdomains():
    pkts = [_dns_query(i, f"s{i}.cdn.example.com") for i in range(200)]
    assert _only(analyze_packets(pkts).alerts, "dnstunnel") == []


def test_dnstunnel_detects_long_unique_subdomains_and_escalates_on_txt():
    pkts = [_dns_query(i, f"{i:040x}.data.evil.example", qtype=16) for i in range(60)]
    (alert,) = _only(analyze_packets(pkts).alerts, "dnstunnel")
    assert alert.dst == "evil.example"
    assert alert.severity.name == "HIGH"  # TXT share >= 50%
    assert alert.evidence["mean_subdomain_length"] == 45.0


def test_nxdomain_counts_responses_not_queries():
    queries = [_dns_query(i, f"x{i}.example") for i in range(50)]
    assert _only(analyze_packets(queries).alerts, "nxdomain") == []
    (alert,) = _only(analyze_packets([_nx(i * 0.5, f"q{i}zz.example{i}.com") for i in range(30)]).alerts, "nxdomain")
    assert alert.src == "10.0.0.20"
    assert alert.evidence["registered_domains"] == 30


# --- baselines --------------------------------------------------------------------


def test_ewma_threshold_has_a_floor_for_perfectly_regular_hosts():
    base = Ewma()
    for _ in range(20):
        base.update(10, 0.1)
    assert base.dev == 0.0
    assert base.threshold(6) == pytest.approx(10 + 6 * 2.5)  # floor: 25% of the mean


def _feed(b: IntervalBaselines, values: Sequence[float]) -> list[Anomaly]:
    out = []
    for i, v in enumerate(values):
        if v:
            out += b.add("h", i * 60.0 + 1, v)
        else:
            out += b.roll(i * 60.0 + 1)
    return out + b.roll(len(values) * 60.0 + 1)


def _baselines(**kw) -> IntervalBaselines:
    params = {"interval": 60.0, "smoothing": 0.1, "warmup": 5, "sensitivity": 6.0, "min_value": 50, "max_entities": 10}
    return IntervalBaselines(**{**params, **kw})


def test_no_alert_during_warmup():
    assert _feed(_baselines(), [10, 10, 10, 500]) == []


def test_spike_after_warmup_alerts_once_and_is_learned_clipped():
    b = _baselines()
    (anomaly,) = _feed(b, [10] * 8 + [500, 600] + [10])
    assert anomaly.intervals == 2
    assert anomaly.peak == 600
    assert b._baselines["h"].mean < 30  # clipped updates: the attack did not become the baseline


def test_silent_intervals_count_as_zero():
    b = _baselines()
    _feed(b, [100] * 6 + [0] * 30)
    assert b._baselines["h"].mean < 10


def test_entity_table_is_bounded():
    b = _baselines(max_entities=3)
    for i in range(10):
        b.add(f"h{i}", 1.0, 1)
    b.roll(61.0)
    assert len(b._baselines) == 3
    assert b.evicted == 7


def test_connrate_needs_a_baseline():
    cfg = Config(connrate=ConnRateConfig(warmup_intervals=3, min_count=20))
    pkts = []
    for minute in range(6):
        n = 200 if minute == 5 else 5
        pkts += [
            udp(minute * 60 + k * 0.1, "10.0.0.20", "10.0.0.10", 1000 + k, sport=9000 + minute * 1000 + k)
            for k in range(n)
        ]
    (alert,) = _only(analyze_packets(pkts, cfg).alerts, "connrate")
    assert alert.evidence["peak_connections_per_interval"] == 200


# --- fragments ------------------------------------------------------------------


def _frags(frame: bytes, size: int, ts: float = 0.0) -> list[tuple[float, bytes, int]]:
    from netguard.lab.synth import fragment

    return [(ts + i * 0.001, f, 1) for i, f in enumerate(fragment(frame, size))]


def test_tiny_fragments_are_reported_and_classified():
    from netguard.engine import analyze_frames
    from netguard.lab.scenarios import ATTACKER, SERVER

    frames = [f for port in range(1, 6) for f in _frags(ATTACKER.tcp(SERVER, 40000, port, SYN), 8, port)]
    (alert,) = _only(analyze_frames(frames).alerts, "fragments")
    assert alert.evidence["kinds"] == {"tiny_first_fragment": 5, "tcp_header_split": 5}
    assert alert.evidence["smallest_fragment_payload_bytes"] == 8


def test_mtu_sized_fragments_and_few_oddities_are_quiet():
    from netguard.engine import analyze_frames
    from netguard.lab.scenarios import SERVER, WORKSTATION

    big = [f for i in range(10) for f in _frags(WORKSTATION.udp(SERVER, 800, 2049, b"\x00" * 4000), 1480, i)]
    assert _only(analyze_frames(big).alerts, "fragments") == []
    few = _frags(WORKSTATION.tcp(SERVER, 40000, 80, SYN), 8)  # 2 suspicious fragments < min_fragments
    assert _only(analyze_frames(few).alerts, "fragments") == []


def test_first_fragment_with_a_complete_header_is_not_tiny():
    """Regression: TCP payload length was compared with the header size."""
    from netguard.lab.scenarios import ATTACKER, SERVER
    from netguard.lab.synth import fragment

    first, _ = fragment(ATTACKER.tcp(SERVER, 40000, 80, SYN, b"y" * 300), 24)[:2]
    pkt = decode(0, first)
    assert pkt is not None
    assert pkt.proto == "tcp"
    det = FragmentDetector(Config())
    assert det._kind(pkt) == "small_fragment"  # small, but the header is intact
