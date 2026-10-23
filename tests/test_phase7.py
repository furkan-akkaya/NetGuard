"""DHCP parsing and lease correlation, explainable confidence, alert correlation."""

import pytest

from netguard.confidence import MAX_SCORE, MIN_SCORE, RULES, assess
from netguard.config import ArpSpoofConfig, Config
from netguard.correlate import correlate
from netguard.dhcp import parse_dhcp
from netguard.engine import analyze_packets
from netguard.lab.scenarios import ATTACKER, GATEWAY, WORKSTATION
from netguard.lab.synth import dhcp_ack
from netguard.models import Packet

from .helpers import arp

# --- DHCP ------------------------------------------------------------------------------------


def test_parse_dhcp_ack():
    payload = dhcp_ack(GATEWAY, "02:00:00:00:bb:02", "10.0.0.77", lease_seconds=600)[42:]
    info = parse_dhcp(payload)
    assert info is not None
    assert (info.msg_name, info.client_mac, info.your_ip, info.server_id, info.lease_seconds) == (
        "ACK",
        "02:00:00:00:bb:02",
        "10.0.0.77",
        "10.0.0.1",
        600,
    )


@pytest.mark.parametrize("cut", [0, 100, 239, 242])  # 242: option 53 without its value
def test_truncated_dhcp_is_none_or_partial(cut):
    payload = dhcp_ack(GATEWAY, "02:00:00:00:bb:02", "10.0.0.77")[42:][:cut]
    info = parse_dhcp(payload)
    assert info is None or info.msg_type is None


def test_option_length_past_the_end_is_ignored():
    payload = bytearray(dhcp_ack(GATEWAY, "02:00:00:00:bb:02", "10.0.0.77")[42:])
    payload[240:] = bytes([53, 200, 5])  # claims 200 bytes of option data
    info = parse_dhcp(bytes(payload))
    assert info is not None
    assert info.msg_type is None


def _dhcp_packet(ts: float, server_ip: str, mac: str, ip: str) -> Packet:
    from netguard.decode import decode

    server = GATEWAY if server_ip == GATEWAY.ip else ATTACKER
    pkt = decode(ts, dhcp_ack(server, mac, ip))
    assert pkt is not None
    return pkt


def _arp_alerts(pkts, config=None):
    return [a for a in analyze_packets(pkts, config).alerts if a.rule_id == "NG-ARP-001"]


OLD, NEW = "02:00:00:00:aa:01", "02:00:00:00:bb:02"


def test_lease_from_the_established_server_explains_the_change():
    pkts = [
        _dhcp_packet(0, GATEWAY.ip, WORKSTATION.mac, WORKSTATION.ip),
        arp(1, 2, "10.0.0.77", OLD, GATEWAY.ip),
        _dhcp_packet(100, GATEWAY.ip, NEW, "10.0.0.77"),
        arp(101, 1, "10.0.0.77", NEW, "10.0.0.77"),
    ]
    assert _arp_alerts(pkts) == []
    # ...but the old MAC claiming the IP back is a conflict again.
    assert len(_arp_alerts([*pkts, arp(200, 2, "10.0.0.77", OLD, GATEWAY.ip)])) == 1


def test_lease_from_a_second_server_explains_nothing():
    pkts = [
        _dhcp_packet(0, GATEWAY.ip, WORKSTATION.mac, WORKSTATION.ip),
        arp(1, 2, "10.0.0.77", OLD, GATEWAY.ip),
        _dhcp_packet(100, ATTACKER.ip, NEW, "10.0.0.77"),
        arp(101, 1, "10.0.0.77", NEW, "10.0.0.77"),
    ]
    assert len(_arp_alerts(pkts)) == 1


def test_configured_servers_and_switch_off():
    pkts = [arp(1, 2, "10.0.0.77", OLD, GATEWAY.ip), _dhcp_packet(100, ATTACKER.ip, NEW, "10.0.0.77")]
    pkts.append(arp(101, 1, "10.0.0.77", NEW, "10.0.0.77"))
    trusted = Config(arpspoof=ArpSpoofConfig(dhcp_servers=[ATTACKER.ip]))
    assert _arp_alerts(pkts, trusted) == []
    off = Config(arpspoof=ArpSpoofConfig(trust_dhcp=False, dhcp_servers=[ATTACKER.ip]))
    assert len(_arp_alerts(pkts, off)) == 1


def test_stale_lease_does_not_explain():
    pkts = [
        arp(1, 2, "10.0.0.77", OLD, GATEWAY.ip),
        _dhcp_packet(100, GATEWAY.ip, NEW, "10.0.0.77"),
        arp(100 + 4000, 1, "10.0.0.77", NEW, "10.0.0.77"),  # beyond dhcp_window_seconds (3600)
    ]
    assert len(_arp_alerts(pkts)) == 1


# --- confidence --------------------------------------------------------------------------------


def test_every_rule_has_a_confidence_model():
    from netguard.detectors import DETECTORS

    assert {r.rule_id for d in DETECTORS for r in d.rules} == set(RULES)


def test_confidence_is_clamped_and_explained():
    high = assess(
        "NG-DNS-001", {"tunnel_record_type_share": 1, "mean_entropy_bits_per_char": 5, "distinct_subdomains": 900}
    )
    assert high is not None
    assert high["score"] == MAX_SCORE  # never 100: evidence is not proof
    assert [f["weight"] for f in high["factors"]] == [20, 10, 10]
    low = assess("NG-DNS-002", {"registered_domains": 1})
    assert low is not None
    assert low["score"] == 25
    assert low["level"] == "low"
    assert assess("NG-NOPE-001", {}) is None
    floor = assess("NG-SCAN-001", {"distinct_ports": 20, "open_ports": list(range(20))})
    assert floor is not None
    assert floor["score"] >= MIN_SCORE


def test_confidence_ignores_malformed_evidence():
    result = assess("NG-SYN-001", {"completion_ratio": "lots", "answer_ratio": None, "distinct_sources": True})
    assert result is not None  # unexpected types count as absent, never crash
    assert result["score"] == 60  # the base: no factor applies when values are unusable
    assert result["factors"] == []


# --- correlation -------------------------------------------------------------------------------


def _alert(alert_id, src, start, end, rule="NG-SCAN-001", sev="MEDIUM", technique="T1046", stage="final", score=50):
    return {
        "alert_id": alert_id,
        "stage": stage,
        "rule_id": rule,
        "title": rule,
        "severity": sev,
        "src": src,
        "dst": "10.0.0.10",
        "first_seen": f"2025-01-01T00:{start:02d}:00+00:00",
        "last_seen": f"2025-01-01T00:{end:02d}:00+00:00",
        "technique": {"id": technique, "name": technique, "url": ""} if technique else None,
        "confidence": {"score": score},
    }


def test_alerts_of_one_actor_close_in_time_form_one_incident():
    alerts = [
        _alert("a", "10.0.0.66", 0, 1),
        _alert("b", "10.0.0.66", 2, 3, rule="NG-SCAN-002", sev="HIGH", score=90),
        _alert("c", "10.0.0.66", 4, 5, rule="NG-DNS-001", technique="T1071.004"),
        _alert("d", "10.0.0.99", 0, 1),
    ]
    incidents = correlate(alerts, gap_seconds=300)
    assert [i["alert_count"] for i in incidents] == [3, 1]
    top = incidents[0]
    assert (top["actor"], top["severity"], top["confidence"]) == ("10.0.0.66", "HIGH", 90)
    assert top["tactics"] == ["Discovery", "Command and Control"]


def test_a_long_gap_starts_a_new_incident():
    incidents = correlate([_alert("a", "10.0.0.66", 0, 1), _alert("b", "10.0.0.66", 40, 41)], gap_seconds=600)
    assert len(incidents) == 2


def test_early_and_final_stages_count_once():
    alerts = [_alert("a", "10.0.0.66", 0, 0, stage="early"), _alert("a", "10.0.0.66", 0, 2, stage="final")]
    (incident,) = correlate(alerts)
    assert incident["alert_count"] == 1
    assert incident["last_seen"].endswith("00:02:00+00:00")


def test_incident_ids_are_deterministic():
    alerts = [_alert("a", "10.0.0.66", 0, 1), _alert("b", "10.0.0.66", 2, 3)]
    assert correlate(alerts)[0]["incident_id"] == correlate(list(reversed(alerts)))[0]["incident_id"]


def test_alert_without_source_correlates_on_its_target():
    flood = _alert("f", None, 0, 1, rule="NG-SYN-001", technique="T1499.001")
    (incident,) = correlate([flood])
    assert incident["actor"] == "10.0.0.10"
    assert incident["tactics"] == ["Impact"]
