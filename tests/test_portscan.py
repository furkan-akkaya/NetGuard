import pytest

from netguard.config import Config, PortScanConfig
from netguard.detectors.portscan import PortScanDetector, probe_type
from netguard.engine import analyze_packets
from netguard.models import ACK, FIN, PSH, RST, SYN, URG, Severity

from .helpers import tcp

SCANNER, TARGET = "10.0.0.66", "10.0.0.10"


@pytest.mark.parametrize(
    ("flags", "expected"),
    [
        (SYN, "SYN"),
        (0, "NULL"),
        (FIN, "FIN"),
        (FIN | PSH | URG, "XMAS"),
        (SYN | ACK, None),  # server reply
        (ACK, None),  # established traffic
        (FIN | ACK, None),  # normal close
        (RST, None),
        (RST | ACK, None),
        (SYN | RST, None),  # malformed, not a classic probe
    ],
)
def test_probe_type(flags, expected):
    assert probe_type(flags) == expected


def _scan(n_ports: int, gap: float = 0.01, flags: int = SYN, src: str = SCANNER):
    return [tcp(i * gap, src, TARGET, 1000 + i, flags) for i in range(n_ports)]


def _cfg(**kw) -> Config:
    return Config(portscan=PortScanConfig(**kw))


def test_scan_above_threshold_produces_one_alert():
    result = analyze_packets(_scan(50), _cfg(min_distinct_ports=15))
    alerts = [a for a in result.alerts if a.detector == "portscan"]
    assert len(alerts) == 1
    a = alerts[0]
    assert (a.src, a.dst) == (SCANNER, TARGET)
    assert a.evidence["distinct_ports"] == 50
    assert a.technique is not None
    assert a.technique.id == "T1046"
    assert "50 distinct TCP ports" in a.summary


def test_below_threshold_is_quiet():
    result = analyze_packets(_scan(14), _cfg(min_distinct_ports=15))
    assert result.alerts == []


def test_repeated_connections_to_one_port_are_not_a_scan():
    pkts = [tcp(i * 0.1, SCANNER, TARGET, 443, SYN, sport=30000 + i) for i in range(500)]
    assert analyze_packets(pkts).alerts == []


def test_open_and_closed_ports_are_reported():
    pkts = []
    for i in range(20):
        port = 1000 + i
        pkts.append(tcp(i * 0.01, SCANNER, TARGET, port, SYN))
        reply = SYN | ACK if port in (1000, 1019) else RST | ACK
        pkts.append(tcp(i * 0.01 + 0.001, TARGET, SCANNER, 40000, reply, sport=port))
    alert = analyze_packets(pkts).alerts[0]
    assert alert.evidence["open_ports"] == [1000, 1019]  # 1000 answered before the threshold
    assert alert.evidence["closed_ports_count"] == 18
    assert "Open: 1000, 1019" in alert.summary


def test_stealth_probe_types_are_called_out():
    alert = analyze_packets(_scan(30, flags=FIN | PSH | URG)).alerts[0]
    assert alert.evidence["probe_types"] == {"XMAS": 30}
    assert "stealth" in alert.summary


def test_large_scan_is_high_severity():
    alert = analyze_packets(_scan(200, gap=0.001), _cfg(high_severity_ports=100)).alerts[0]
    assert alert.severity == Severity.HIGH


def test_allowlisted_scanner_is_ignored():
    cfg = Config(allowlist=["10.0.0.0/24"])
    assert analyze_packets(_scan(100), cfg).alerts == []


def test_slow_scan_evades_the_window():
    """Documented limitation: one probe per 15s never reaches 15 ports per 60s."""
    assert analyze_packets(_scan(100, gap=15.0)).alerts == []


def test_separate_bursts_become_separate_incidents():
    first = _scan(20)
    second = [tcp(500 + i * 0.01, SCANNER, TARGET, 5000 + i, SYN) for i in range(20)]
    alerts = analyze_packets(first + second).alerts
    assert len(alerts) == 2


def test_detector_ignores_non_tcp():
    det = PortScanDetector(Config())
    from netguard.models import Packet

    assert list(det.on_packet(Packet(ts=0, length=1, proto="udp", src_ip="a", dst_ip="b"))) == []
