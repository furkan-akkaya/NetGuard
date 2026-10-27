"""The lab measurement script eval/lab/live_delay.py."""

import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from netguard.lab.scenarios import ATTACKER, SERVER
from netguard.lab.synth import syn_probe, write_pcap

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "eval" / "lab"))
import live_delay  # type: ignore[import-not-found]  # eval/lab is not a package


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).isoformat()


@pytest.fixture
def scan_pcap(tmp_path):
    # 40 closed ports, one probe every 0.1 s: the portscan rule (15 distinct
    # ports) crosses its threshold with the 15th probe, at t = 101.4.
    frames = [f for i in range(40) for f in syn_probe(ATTACKER, SERVER, 100.0 + i * 0.1, 1 + i, open_=False)]
    path = tmp_path / "scan.pcap"
    write_pcap(path, frames)
    return path


def test_threshold_crossing_is_the_packet_that_crossed_not_the_newest_evidence(scan_pcap, tmp_path):
    crossed = live_delay.threshold_crossings(scan_pcap)
    key = ("NG-SCAN-001", ATTACKER.ip, SERVER.ip)
    assert crossed[key] == pytest.approx(101.4)

    # A live report 0.25 s after the crossing whose incident had grown to the
    # 20th probe: newest evidence 0.05 s old, threshold delay 0.25 s.
    alert = {
        "stage": "early",
        "rule_id": "NG-SCAN-001",
        "src": ATTACKER.ip,
        "dst": SERVER.ip,
        "first_seen": _iso(100.0),
        "last_seen": _iso(101.6),
        "reported_at": _iso(101.65),
    }
    jsonl = tmp_path / "live.jsonl"
    jsonl.write_text(json.dumps(alert) + "\n", encoding="utf-8")
    (row,) = live_delay.delays(jsonl, crossed)
    assert row["after_newest_evidence_s"] == pytest.approx(0.05)
    assert row["after_threshold_crossed_s"] == pytest.approx(0.25)
    assert row["after_incident_first_seen_s"] == pytest.approx(1.65)


def test_without_pcap_no_threshold_delay_is_claimed(scan_pcap, tmp_path, capsys):
    alert = {
        "stage": "early",
        "rule_id": "NG-SCAN-001",
        "src": ATTACKER.ip,
        "dst": SERVER.ip,
        "first_seen": _iso(100.0),
        "last_seen": _iso(101.6),
        "reported_at": _iso(101.65),
    }
    jsonl = tmp_path / "live.jsonl"
    jsonl.write_text(json.dumps(alert) + "\n", encoding="utf-8")
    assert live_delay.main([str(jsonl)]) == 0
    err = capsys.readouterr().err
    assert "not the delay after the threshold" in err
    assert "threshold-crossing delay not computed" in err
    assert live_delay.main([str(jsonl), "--pcap", str(scan_pcap)]) == 0
    assert "largest delay after the threshold-crossing packet: 0.250s" in capsys.readouterr().err
