"""Independent, hand-labelled Zeek-format fixtures; these do not run Zeek."""

import json

import pytest

from netguard.cli import main
from netguard.lab.compare import compare_flows, read_zeek
from netguard.lab.manifest import ManifestError
from netguard.lab.scenarios import ATTACKER, SERVER, T0
from netguard.lab.synth import syn_probe, write_pcap


def reference_row(state="REJ", port=81):
    return {
        "ts": T0,
        "id.orig_h": ATTACKER.ip,
        "id.orig_p": 40081,
        "id.resp_h": SERVER.ip,
        "id.resp_p": port,
        "proto": "tcp",
        "conn_state": state,
    }


def pair(tmp_path):
    capture = tmp_path / "probe.pcap"
    write_pcap(capture, syn_probe(ATTACKER, SERVER, T0, 81, open_=False))
    log = tmp_path / "conn.log"
    log.write_text(json.dumps(reference_row()) + "\n")
    return capture, log


def test_same_state_matches_and_mismatch_is_nonzero(tmp_path, capsys):
    capture, log = pair(tmp_path)
    assert main(["lab", "compare-flows", str(capture), str(log)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["matched"] == 1
    assert not result["mismatches"]
    assert len(result["capture_sha256"]) == len(result["zeek_log_sha256"]) == 64
    log.write_text(json.dumps(reference_row("S0")) + "\n")
    assert main(["lab", "compare-flows", str(capture), str(log)]) == 1
    mismatch = json.loads(capsys.readouterr().out)
    assert mismatch["only_netguard"] == mismatch["only_zeek"] == 1
    assert len(mismatch["mismatches"]) == 2


def test_repeated_connections_are_not_silently_deduplicated(tmp_path):
    capture, log = pair(tmp_path)
    log.write_text(log.read_text() * 2)
    result = compare_flows(capture, log)
    assert not result["equal"]
    assert result["only_zeek"] == 1


def test_matching_histograms_cannot_hide_wrong_endpoints(tmp_path):
    capture, log = pair(tmp_path)
    log.write_text(json.dumps(reference_row(port=82)) + "\n")
    assert compare_flows(capture, log)["matched"] == 0


@pytest.mark.parametrize(
    "row",
    [
        "#separator \\x09",
        "[]",
        "{}",
        '{"proto":"tcp"}',
        json.dumps(reference_row(port=True)),
        json.dumps(reference_row(state="NONEXISTENT")),
        "{invalid",
    ],
)
def test_malformed_log_is_rejected(tmp_path, row):
    log = tmp_path / "bad.log"
    log.write_text(row + "\n")
    with pytest.raises(ManifestError):
        read_zeek(log)


def test_empty_or_unrelated_logs_are_not_success(tmp_path):
    log = tmp_path / "conn.log"
    log.write_text("\n" + json.dumps({"proto": "icmp"}) + "\n")
    with pytest.raises(ManifestError, match="no TCP/UDP"):
        read_zeek(log)
    log.write_bytes(b"x" * 1_048_577)
    with pytest.raises(ManifestError, match="exceeds"):
        read_zeek(log)


def test_truncation_is_rejected_and_non_tcp_rows_are_counted(tmp_path):
    capture, log = pair(tmp_path)
    log.write_text(log.read_text() + json.dumps({"proto": "icmp"}) + "\n")
    assert compare_flows(capture, log)["zeek_non_tcp_udp_ignored"] == 1
    capture.write_bytes(capture.read_bytes()[:-5])
    with pytest.raises(ManifestError, match="truncated"):
        compare_flows(capture, log)
