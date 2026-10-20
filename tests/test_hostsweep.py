from netguard.config import Config, HostSweepConfig
from netguard.engine import analyze_packets
from netguard.models import ACK, SYN

from .helpers import arp, icmp, tcp

SCANNER = "10.0.0.66"


def test_ping_sweep_detected_with_alive_hosts():
    pkts = []
    for i in range(1, 41):
        pkts.append(icmp(i * 0.01, SCANNER, f"10.0.5.{i}"))
        if i in (1, 7):
            pkts.append(icmp(i * 0.01 + 0.001, f"10.0.5.{i}", SCANNER, icmp_type=0))
    alerts = analyze_packets(pkts).alerts
    assert len(alerts) == 1
    a = alerts[0]
    assert a.detector == "hostsweep"
    assert a.src == SCANNER
    assert a.evidence["distinct_hosts"] == 40
    assert a.evidence["alive_hosts"] == ["10.0.5.1", "10.0.5.7"]
    assert a.technique is not None
    assert a.technique.id == "T1018"


def test_arp_sweep_detected():
    pkts = [arp(i * 0.01, 1, SCANNER, "02:00:00:00:00:66", f"10.0.0.{i}") for i in range(1, 60)]
    alerts = [a for a in analyze_packets(pkts).alerts if a.detector == "hostsweep"]
    assert len(alerts) == 1
    assert alerts[0].evidence["methods"] == {"ARP": 59}


def test_arp_address_conflict_probes_are_ignored():
    # RFC 5227 probes use sender IP 0.0.0.0
    pkts = [arp(i * 0.01, 1, "0.0.0.0", "02:00:00:00:00:99", f"10.0.0.{i}") for i in range(1, 60)]
    assert analyze_packets(pkts).alerts == []


def test_tcp_to_many_public_hosts_is_not_a_sweep():
    """A browser opening connections to many CDN hosts."""
    pkts = [tcp(i * 0.05, "10.0.0.20", f"93.184.0.{i}", 443, SYN) for i in range(1, 80)]
    assert analyze_packets(pkts).alerts == []


def test_tcp_horizontal_scan_of_internal_hosts():
    pkts = [tcp(i * 0.01, SCANNER, f"192.168.1.{i}", 445, SYN) for i in range(1, 30)]
    pkts.append(tcp(0.5, "192.168.1.3", SCANNER, 40000, SYN | ACK, sport=445))
    alerts = analyze_packets(pkts).alerts
    assert [a.detector for a in alerts] == ["hostsweep"]
    assert alerts[0].evidence["alive_hosts"] == ["192.168.1.3"]


def test_public_tcp_counted_when_filter_disabled():
    cfg = Config(hostsweep=HostSweepConfig(tcp_private_only=False))
    pkts = [tcp(i * 0.05, "10.0.0.20", f"93.184.0.{i}", 443, SYN) for i in range(1, 80)]
    assert len(analyze_packets(pkts, cfg).alerts) == 1


def test_established_traffic_is_not_a_probe():
    pkts = [tcp(i * 0.01, SCANNER, f"10.0.9.{i}", 445, ACK) for i in range(1, 50)]
    assert analyze_packets(pkts).alerts == []
