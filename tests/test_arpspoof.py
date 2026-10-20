from netguard.config import ArpSpoofConfig, Config
from netguard.engine import analyze_packets
from netguard.models import Severity

from .helpers import arp

GW_IP, GW_MAC = "10.0.0.1", "02:00:00:00:00:01"
VICTIM_IP, VICTIM_MAC = "10.0.0.20", "02:00:00:00:00:20"
EVIL_MAC = "02:00:00:00:00:66"
REQUEST, REPLY = 1, 2


def _baseline():
    return [
        arp(0.0, REQUEST, VICTIM_IP, VICTIM_MAC, GW_IP),
        arp(0.001, REPLY, GW_IP, GW_MAC, VICTIM_IP, VICTIM_MAC),
    ]


def test_stable_bindings_are_quiet():
    pkts = _baseline() * 1 + [arp(10.0 + i, REPLY, GW_IP, GW_MAC, VICTIM_IP, VICTIM_MAC) for i in range(10)]
    assert analyze_packets(pkts).alerts == []


def test_binding_change_alerts_with_unsolicited_flag():
    pkts = [*_baseline(), arp(20.0, REPLY, GW_IP, EVIL_MAC, VICTIM_IP, VICTIM_MAC)]
    alerts = analyze_packets(pkts).alerts
    assert len(alerts) == 1
    a = alerts[0]
    assert a.detector == "arpspoof"
    assert (a.src, a.dst) == (EVIL_MAC, GW_IP)
    assert a.severity == Severity.MEDIUM
    assert a.evidence["unsolicited_reply"] is True
    assert a.evidence["previous_mac"] == GW_MAC


def test_solicited_reply_is_not_flagged_unsolicited():
    pkts = [
        *_baseline(),
        arp(20.0, REQUEST, VICTIM_IP, VICTIM_MAC, GW_IP),
        arp(20.1, REPLY, GW_IP, EVIL_MAC, VICTIM_IP, VICTIM_MAC),
    ]
    assert analyze_packets(pkts).alerts[0].evidence["unsolicited_reply"] is False


def test_continuous_poisoning_does_not_flood_alerts():
    pkts = _baseline()
    for i in range(50):  # attacker and gateway fight over the IP every second
        pkts.append(arp(10.0 + i, REPLY, GW_IP, EVIL_MAC, VICTIM_IP, VICTIM_MAC))
        pkts.append(arp(10.5 + i, REPLY, GW_IP, GW_MAC, VICTIM_IP, VICTIM_MAC))
    alerts = analyze_packets(pkts).alerts
    # one MEDIUM on first change, one HIGH escalation on flip-flop; then silence
    assert [a.severity for a in alerts] == [Severity.MEDIUM, Severity.HIGH]
    assert all(a.src == EVIL_MAC for a in alerts)  # suspect is the attacker, never the gateway


def test_critical_ip_is_high_severity():
    cfg = Config(arpspoof=ArpSpoofConfig(critical_ips=[GW_IP]))
    pkts = [*_baseline(), arp(20.0, REPLY, GW_IP, EVIL_MAC, VICTIM_IP, VICTIM_MAC)]
    alert = analyze_packets(pkts, cfg).alerts[0]
    assert alert.severity == Severity.HIGH
    assert "critical" in alert.summary


def test_realert_after_period():
    cfg = Config(arpspoof=ArpSpoofConfig(realert_seconds=60))
    pkts = [
        *_baseline(),
        arp(10.0, REPLY, GW_IP, EVIL_MAC, VICTIM_IP, VICTIM_MAC),
        arp(11.0, REPLY, GW_IP, GW_MAC, VICTIM_IP, VICTIM_MAC),  # HIGH escalation
        arp(12.0, REPLY, GW_IP, EVIL_MAC, VICTIM_IP, VICTIM_MAC),  # suppressed
        arp(200.0, REPLY, GW_IP, GW_MAC, VICTIM_IP, VICTIM_MAC),  # period elapsed
    ]
    assert len(analyze_packets(pkts, cfg).alerts) == 3


def test_zero_sender_ip_is_ignored():
    pkts = [arp(0, REQUEST, "0.0.0.0", VICTIM_MAC, GW_IP), arp(1, REQUEST, "0.0.0.0", EVIL_MAC, GW_IP)]
    assert analyze_packets(pkts).alerts == []
