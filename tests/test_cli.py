import csv
import io
import json
import subprocess
import sys
from pathlib import Path

import pytest

from netguard.cli import EXIT_ERROR, EXIT_OK, main
from netguard.lab.scenarios import get
from netguard.lab.synth import write_pcap


@pytest.fixture
def scan_pcap(tmp_path):
    path = tmp_path / "scan.pcap"
    write_pcap(path, get("syn_scan_1000").build())
    return path


def test_analyze_text(scan_pcap, capsys):
    assert main(["analyze", str(scan_pcap)]) == EXIT_OK
    out = capsys.readouterr().out
    assert "Alerts: 2 (2 HIGH)" in out  # the window rule and TRW both see the scan
    assert "TCP port scan: 10.0.0.66 -> 10.0.0.10" in out
    assert "Scan detected by connection outcomes (TRW): 10.0.0.66 -> 10.0.0.10" in out
    assert "Open: 22, 80, 443" in out


def test_analyze_json(scan_pcap, capsys):
    assert main(["analyze", "-f", "json", str(scan_pcap)]) == EXIT_OK
    doc = json.loads(capsys.readouterr().out)
    assert doc["stats"]["packets"] == 2003
    assert doc["alerts"][0]["technique"]["id"] == "T1046"
    assert doc["alerts"][0]["evidence"]["open_ports"] == [22, 80, 443]


def test_analyze_jsonl(scan_pcap, capsys):
    assert main(["analyze", "-f", "jsonl", str(scan_pcap)]) == EXIT_OK
    lines = capsys.readouterr().out.strip().splitlines()
    assert sorted(json.loads(line)["detector"] for line in lines) == ["portscan", "trw"]


def test_missing_file_is_a_clean_error(tmp_path, capsys):
    assert main(["analyze", str(tmp_path / "nope.pcap")]) == EXIT_ERROR
    assert "No such file" in capsys.readouterr().err


def test_bad_config_is_a_clean_error(scan_pcap, tmp_path, capsys):
    cfg = tmp_path / "bad.toml"
    cfg.write_text("[nope]\n")
    assert main(["analyze", "-c", str(cfg), str(scan_pcap)]) == EXIT_ERROR
    assert "unknown sections" in capsys.readouterr().err


def test_lab_generate_and_list(tmp_path, capsys):
    assert main(["lab", "generate", str(tmp_path), "--scenario", "arp_sweep"]) == EXIT_OK
    assert (tmp_path / "arp_sweep.pcap").exists()
    assert main(["lab", "list"]) == EXIT_OK
    assert "syn_scan_1000" in capsys.readouterr().out


def test_flows_csv(scan_pcap, capsys):
    assert main(["flows", str(scan_pcap)]) == EXIT_OK
    rows = list(csv.DictReader(io.StringIO(capsys.readouterr().out)))
    assert len(rows) == 1000
    assert {r["state"] for r in rows} == {"REJ", "RSTO"}
    assert rows[0]["src_ip"] == "10.0.0.66"


def test_flows_jsonl(scan_pcap, capsys):
    assert main(["flows", "-f", "jsonl", str(scan_pcap)]) == EXIT_OK
    lines = capsys.readouterr().out.strip().splitlines()
    assert len(lines) == 1000
    assert json.loads(lines[0])["proto"] == "tcp"


def test_alert_contract_v1(scan_pcap, capsys):
    """The alert JSON fields are a public contract: changing them breaks consumers."""
    assert main(["analyze", "-f", "json", str(scan_pcap)]) == EXIT_OK
    doc = json.loads(capsys.readouterr().out)
    assert doc["schema_version"] == "1.0"
    assert doc["capture"] == {"format": "pcap", "linktypes": [1], "truncated": False, "skipped_blocks": 0}
    alert = doc["alerts"][0]
    assert set(alert) == {
        "schema_version",
        "alert_id",
        "rule_id",
        "detector",
        "title",
        "severity",
        "first_seen",
        "last_seen",
        "src",
        "dst",
        "summary",
        "technique",
        "evidence",
    }
    assert alert["rule_id"] == "NG-SCAN-001"
    assert len(alert["alert_id"]) == 20


def test_alert_ids_are_deterministic(scan_pcap, capsys):
    main(["analyze", "-f", "jsonl", str(scan_pcap)])
    first = capsys.readouterr().out
    main(["analyze", "-f", "jsonl", str(scan_pcap)])
    assert [json.loads(x)["alert_id"] for x in capsys.readouterr().out.splitlines()] == [
        json.loads(x)["alert_id"] for x in first.splitlines()
    ]


def test_truncated_capture_warns(scan_pcap, tmp_path, capsys):
    cut = tmp_path / "cut.pcap"
    cut.write_bytes(scan_pcap.read_bytes()[:-7])
    assert main(["analyze", str(cut)]) == EXIT_OK
    assert "truncated" in capsys.readouterr().err


def test_corrupt_capture_is_a_clean_error(tmp_path, capsys):
    bad = tmp_path / "bad.pcap"
    bad.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20 + b"\x00\x00\x00\x00" * 2 + b"\xff\xff\xff\xff" * 2)
    assert main(["analyze", str(bad)]) == EXIT_ERROR
    assert "exceeds" in capsys.readouterr().err


def test_closed_stdout_pipe_is_not_an_error(scan_pcap):
    """Regression: `netguard flows x.pcap | head` printed a BrokenPipeError traceback."""
    proc = subprocess.Popen(
        [sys.executable, "-m", "netguard.cli", "flows", str(scan_pcap)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert proc.stdout is not None
    assert proc.stderr is not None
    proc.stdout.readline()
    proc.stdout.close()  # the reader goes away, like `head -1`
    err = proc.stderr.read()
    assert proc.wait(timeout=30) == EXIT_OK
    assert b"Broken pipe" not in err
    assert b"Traceback" not in err


def test_rules_lists_every_rule_with_its_state(tmp_path, capsys):
    cfg = tmp_path / "c.toml"
    cfg.write_text("[volume]\nenabled = false\n")
    assert main(["rules", "-f", "json", "-c", str(cfg)]) == EXIT_OK
    rows = {r["rule_id"]: r for r in json.loads(capsys.readouterr().out)}
    assert len(rows) == 11
    assert rows["NG-VOL-001"]["enabled"] is False
    assert rows["NG-SYN-001"]["technique"] == "T1499.001"
    for r in rows.values():
        assert (Path(__file__).parent.parent / r["doc"]).exists(), r["doc"]
