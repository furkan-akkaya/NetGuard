from netguard.cli import main
from netguard.lab.scenarios import get
from netguard.lab.synth import write_pcap
from netguard.report import render_report

HOSTILE = '"><script>alert(1)</script><img src=x onerror=alert(2)>'


def _alert(**kw):
    base = {
        "alert_id": "a1",
        "rule_id": "NG-DNS-001",
        "title": "Possible DNS tunnelling",
        "severity": "HIGH",
        "first_seen": "2025-01-01T00:00:00+00:00",
        "last_seen": "2025-01-01T00:01:00+00:00",
        "src": "10.0.0.20",
        "dst": HOSTILE,
        "summary": f"queried {HOSTILE}",
        "technique": {"id": "T1071.004", "name": "DNS", "url": "https://attack.mitre.org/techniques/T1071/004/"},
        "evidence": {"sample_names": [HOSTILE]},
    }
    return {**base, **kw}


def test_report_escapes_every_capture_string():
    stats = {"protocols": {HOSTILE: 1}, "flows": {"top_services": [{"service": HOSTILE, "flows": 1}]}}
    page = render_report(stats, [_alert()], HOSTILE, meta={HOSTILE: HOSTILE})
    assert "<script>" not in page
    assert "<img" not in page
    assert "&lt;script&gt;" in page
    assert "Content-Security-Policy" in page


def test_report_orders_by_severity_and_handles_empty_stats():
    page = render_report({}, [_alert(severity="LOW", alert_id="low"), _alert(alert_id="high")], "x.pcap")
    assert page.index("id high") < page.index("id low")
    assert "No alerts." in render_report({}, [], "x.pcap")


def test_cli_html_report(tmp_path, capsys):
    path = tmp_path / "scan.pcap"
    write_pcap(path, get("syn_scan_1000").build())
    assert main(["analyze", "-f", "html", str(path)]) == 0
    out = capsys.readouterr().out
    assert out.startswith("<!doctype html>")
    assert "NG-SCAN-002" in out
