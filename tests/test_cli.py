import json

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
    assert "Alerts: 1 (1 HIGH)" in out
    assert "TCP port scan: 10.0.0.66 -> 10.0.0.10" in out
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
    assert len(lines) == 1
    assert json.loads(lines[0])["detector"] == "portscan"


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
