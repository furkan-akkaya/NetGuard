"""Ground-truth scoring, integrity rejection and CLI behavior on actual files.

These captures are generated fixtures, never evidence of real-network accuracy.
"""

import hashlib
import json
import os
from dataclasses import replace

import dpkt
import pytest

from netguard import __version__
from netguard.cli import main
from netguard.lab.manifest import ManifestError, evaluate_case, load_manifest, run_manifest, summarize
from netguard.lab.scenarios import get
from netguard.lab.synth import write_pcap


def make_case(tmp_path, scenario="syn_scan_1000", *, kind="attack", provenance="synthetic", expected=None):
    sc = get(scenario)
    capture = tmp_path / f"{scenario}.pcap"
    write_pcap(capture, sc.build())
    expected = sc.expected if expected is None else expected
    labels = ", ".join(
        "{detector = " + json.dumps(d) + ", entity = " + json.dumps(e) + "}" for d, e in sorted(expected)
    )
    text = (
        "schema_version = 1\n[[captures]]\n"
        f'name = "{scenario}"\npath = "{capture.name}"\n'
        f'sha256 = "{hashlib.sha256(capture.read_bytes()).hexdigest()}"\n'
        f'kind = "{kind}"\nprovenance = "{provenance}"\n'
        f'tool = "netguard lab generate"\ntool_version = "{__version__}"\n'
        f'command = "generated test fixture"\nexpected = [{labels}]\n'
    )
    manifest = tmp_path / "captures.toml"
    manifest.write_text(text)
    return manifest, capture


def test_manifest_cli_scores_and_deduplicates_early_and_final(tmp_path, capsys):
    manifest, _ = make_case(tmp_path)
    assert main(["lab", "evaluate", "--manifest", str(manifest), "-f", "json", "--strict"]) == 0
    report = json.loads(capsys.readouterr().out)
    row = report["captures"][0]
    assert len(row["tp"]) == 2
    assert not row["fp"]
    assert not row["fn"]
    assert row["alerts"] == 2  # early and final must not double the count
    assert report["by_provenance"]["synthetic"]["precision"] == 1
    assert row["tool_version"] == __version__
    assert row["replay_incident_delays_seconds"]
    assert all(d >= 0 for d in row["replay_incident_delays_seconds"])
    assert "not measured live" in report["delay_scope"]
    assert len(row["config_sha256"]) == 64


def test_known_false_positive_has_entity_score_and_alert_rate(tmp_path, capsys):
    manifest, _ = make_case(tmp_path, "monitoring_poller", kind="benign", expected=set())
    assert main(["lab", "evaluate", "--manifest", str(manifest), "--strict"]) == 1
    assert "synthetic captures" in capsys.readouterr().out
    row = run_manifest(manifest)["captures"][0]
    assert len(row["fp"]) == 1  # one entity, several incidents
    assert row["alerts"] == 3
    assert row["duration_seconds"] == pytest.approx(121.451)
    assert row["benign_alerts_per_hour"] == pytest.approx(3 * 3600 / 121.451)


def test_config_changes_detection_and_is_pinned(tmp_path):
    manifest, _ = make_case(tmp_path)
    original = run_manifest(manifest)["captures"][0]
    cfg = tmp_path / "off.toml"
    cfg.write_text("[portscan]\nenabled = false\n[trw]\nenabled = false\n")
    manifest.write_text(manifest.read_text() + 'config = "off.toml"\n')
    changed = run_manifest(manifest)["captures"][0]
    assert len(changed["fn"]) == 2
    assert not changed["tp"]
    assert original["config_sha256"] != changed["config_sha256"]


def test_provenances_have_separate_scores(tmp_path):
    manifest, _ = make_case(tmp_path)
    first = manifest.read_text().split("[[captures]]")[1]
    other, _ = make_case(tmp_path, "benign_office", kind="benign", provenance="lab", expected=set())
    other.write_text(other.read_text() + "\n[[captures]]" + first)
    report = run_manifest(other)
    assert set(report["by_provenance"]) == {"synthetic", "lab"}
    assert report["by_provenance"]["lab"]["recall"] is None
    assert report["by_provenance"]["synthetic"]["captures"] == 1


@pytest.mark.parametrize(
    ("change", "match"),
    [
        (lambda s: s.replace("schema_version = 1", "schema_version = 2"), "schema_version"),
        (lambda s: s.replace("schema_version = 1", "schema_version = true"), "requires"),
        (lambda s: s + "surprise = 1\n", "unknown fields"),
        (lambda s: s.replace('kind = "attack"', 'kind = "oops"'), "invalid kind"),
        (lambda s: s.replace('provenance = "synthetic"', 'provenance = "real"'), "invalid kind"),
        (lambda s: s.replace('detector = "portscan"', 'detector = "typo"'), "unknown detector"),
        (lambda s: s.replace('path = "syn_scan_1000.pcap"', 'path = "-"'), "stdin"),
        (lambda s: s.replace('tool = "netguard lab generate"', 'tool = ""'), "non-empty"),
        (lambda s: s.replace(f'tool_version = "{__version__}"\n', ""), "tool_version"),
        (lambda s: s.replace('kind = "attack"', 'kind = "benign"'), "benign needs"),
        (lambda s: s.replace("expected = [", "expected = [1, "), "each expected"),
        (lambda s: s + "note = 42\n", "note must"),
    ],
)
def test_bad_manifest_rejected(tmp_path, change, match):
    manifest, _ = make_case(tmp_path)
    manifest.write_text(change(manifest.read_text()))
    with pytest.raises(ManifestError, match=match):
        load_manifest(manifest)


def test_no_partial_score_on_integrity_failure(tmp_path, capsys):
    manifest, capture = make_case(tmp_path)
    capture.write_bytes(capture.read_bytes() + b"altered")
    assert main(["lab", "evaluate", "--manifest", str(manifest)]) == 2
    out = capsys.readouterr()
    assert not out.out
    assert "SHA-256 mismatch" in out.err


def test_invalid_hash_and_duplicate_capture_rejected(tmp_path):
    manifest, _ = make_case(tmp_path)
    original = manifest.read_text()
    manifest.write_text(original.replace('sha256 = "', 'sha256 = "g'))
    with pytest.raises(ManifestError, match="64 hexadecimal"):
        load_manifest(manifest)
    manifest.write_text(original + "\n[[captures]]" + original.split("[[captures]]")[1])
    with pytest.raises(ManifestError, match="duplicate capture name"):
        load_manifest(manifest)
    manifest.write_text(manifest.read_text().replace('name = "syn_scan_1000"', 'name = "second"', 1))
    with pytest.raises(ManifestError, match="duplicate capture bytes"):
        load_manifest(manifest)


def test_truncated_and_empty_captures_cannot_be_evidence(tmp_path):
    manifest, capture = make_case(tmp_path)
    case = load_manifest(manifest)[0]
    for data in (capture.read_bytes()[:-5], b""):
        capture.write_bytes(data)
        with pytest.raises(ManifestError, match="truncated or empty"):
            evaluate_case(replace(case, sha256=hashlib.sha256(data).hexdigest()))


def test_special_file_does_not_block(tmp_path):
    manifest, _ = make_case(tmp_path)
    fifo = tmp_path / "capture.fifo"
    os.mkfifo(fifo)
    with pytest.raises(ManifestError, match="regular file"):
        evaluate_case(replace(load_manifest(manifest)[0], path=fifo))


def test_manifest_size_syntax_and_structure_errors(tmp_path, capsys):
    path = tmp_path / "bad.toml"
    for data in (b"x" * 1_048_577, b"\xff", b"[broken", b"schema_version=1\ncaptures=[]"):
        path.write_bytes(data)
        assert main(["lab", "evaluate", "--manifest", str(path)]) == 2
        assert "Traceback" not in capsys.readouterr().err


def test_decreasing_timestamps_are_a_warning_not_a_failure(tmp_path):
    # Multi-interface pcapng files are often slightly out of order; that is not invalid evidence.
    manifest, capture = make_case(tmp_path)
    frames = get("syn_scan_1000").build()
    with capture.open("wb") as stream:
        writer = dpkt.pcap.Writer(stream)
        for ts, buf in [frames[1], frames[0]]:
            writer.writepkt(buf, ts=ts)
    case = replace(load_manifest(manifest)[0], sha256=hashlib.sha256(capture.read_bytes()).hexdigest())
    row = evaluate_case(case)
    assert any("out of order" in w for w in row["warnings"])


def test_zero_duration_has_no_invented_rate():
    row = {
        "tp": [],
        "fp": [],
        "fn": [],
        "kind": "benign",
        "duration_seconds": 0,
        "alerts": 1,
        "replay_incident_delays_seconds": [],
        "warnings": [],
    }
    summary = summarize([row])
    assert summary["benign_alerts_per_hour"] is None
    assert summary["precision"] is None
    assert summary["recall"] is None


def test_synthetic_defaults_remain_supported(capsys):
    assert main(["lab", "evaluate"]) == 0
    assert "TP=20, FP=3, FN=1" in capsys.readouterr().out
    assert main(["lab", "evaluate", "--strict"]) == 1
    capsys.readouterr()
    assert main(["lab", "evaluate", "-f", "json"]) == 2
    assert "requires --manifest" in capsys.readouterr().err


def test_missing_capture_is_an_error_not_a_traceback(tmp_path, capsys):
    manifest, capture = make_case(tmp_path)
    capture.unlink()
    assert main(["lab", "evaluate", "--manifest", str(manifest)]) == 2
    err = capsys.readouterr().err
    assert "Traceback" not in err
    assert "syn_scan_1000" in err
