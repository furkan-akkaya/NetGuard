from netguard.engine import Engine, analyze_packets
from netguard.models import SYN, Alert, Packet

from .helpers import icmp, tcp


def test_idle_gap_closes_incident_before_next_packet():
    """Regression: the packet that ends an idle gap must not extend the old incident."""
    burst1 = [icmp(i * 0.01, "10.0.0.5", f"10.0.1.{i}") for i in range(1, 31)]
    burst2 = [icmp(60 + i * 0.01, "10.0.0.5", f"10.0.1.{i}") for i in range(1, 31)]
    alerts = analyze_packets(burst1 + burst2).alerts
    assert len(alerts) == 2
    assert alerts[0].last_seen < 1.0


def test_stats_and_flows():
    pkts = [
        tcp(0, "10.0.0.1", "10.0.0.2", 80, SYN, sport=1234),
        tcp(0.1, "10.0.0.2", "10.0.0.1", 1234, SYN, sport=80),  # reverse direction, same flow
        tcp(0.2, "10.0.0.1", "10.0.0.3", 80, SYN, sport=1234),
    ]
    stats = analyze_packets(pkts).stats
    assert stats.packets == 3
    assert stats.flows_total == 2
    assert stats.protocols["tcp"] == 3
    assert stats.duration == 0.2


def test_decode_errors_are_counted_not_raised():
    engine = Engine()
    engine.process_frame(0.0, b"\x00\x01", 1)
    assert engine.finish().stats.decode_errors == 1


def test_on_alert_callback_streams_alerts():
    seen: list[Alert] = []
    engine = Engine(on_alert=seen.append)
    for i in range(30):
        engine.process(icmp(i * 0.01, "10.0.0.66", f"10.0.3.{i}"))
    engine.process(Packet(ts=100.0, length=1, proto="other"))  # tick closes the incident
    assert len(seen) == 1
    engine.finish()
    assert len(seen) == 1
