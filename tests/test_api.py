"""Integration tests for the REST API: real HTTP layer, real SQLite, real worker processes."""

import json
import struct
import time

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from netguard.jobs import JobLimits
from netguard.lab.scenarios import get
from netguard.lab.synth import write_pcap
from netguard.web.app import create_app, safe_filename
from netguard.web.settings import ServerSettings, SettingsError

API = "/api/v1"
TOKEN = "t" * 32


def _pcap_bytes(tmp_path, scenario="syn_scan_1000"):
    path = tmp_path / f"{scenario}.pcap"
    write_pcap(path, get(scenario).build())
    return path.read_bytes()


@pytest.fixture
def server(tmp_path):
    settings = ServerSettings(data_dir=tmp_path / "data", run_jobs=False, max_upload_bytes=2_000_000)
    app = create_app(settings)
    with TestClient(app) as client:
        yield client, app


def _upload(client, data: bytes, name: str = "scan.pcap", **kw):
    return client.post(f"{API}/captures", params={"filename": name}, content=data, **kw)


def _analyse(client, app, capture_id: str, config=None):
    r = client.post(f"{API}/captures/{capture_id}/analyses", json={"config": config or {}})
    assert r.status_code == 202, r.text
    assert r.json()["status"] == "queued"
    assert app.state.runner.run_pending() == 1
    return client.get(f"{API}/analyses/{r.json()['id']}").json()


def test_health_and_openapi(server):
    client, _ = server
    assert client.get(f"{API}/health").json()["status"] == "ok"
    spec = client.get(f"{API}/openapi.json").json()
    assert spec["info"]["title"] == "NetGuard API"
    assert f"{API}/alerts" in spec["paths"]


def test_full_workflow_upload_analyse_search(server, tmp_path):
    client, app = server
    r = _upload(client, _pcap_bytes(tmp_path))
    assert r.status_code == 201
    capture = r.json()
    assert capture["format"] == "pcap"

    analysis = _analyse(client, app, capture["id"])
    assert analysis["status"] == "done", analysis["error"]
    assert analysis["alert_count"] == 2
    assert analysis["flow_count"] == 1000
    assert analysis["stats"]["packets"] == 2003

    alerts = client.get(f"{API}/alerts", params={"analysis_id": analysis["id"], "sort": "rule_id"}).json()
    assert alerts["total"] == 2
    assert [a["rule_id"] for a in alerts["items"]] == ["NG-SCAN-001", "NG-SCAN-002"]
    one = client.get(f"{API}/alerts/{alerts['items'][0]['id']}").json()
    assert one["evidence"]["open_ports"] == [22, 80, 443]

    flows = client.get(f"{API}/analyses/{analysis['id']}/flows", params={"state": "RSTO", "limit": 10}).json()
    assert flows["total"] == 3
    assert {f["dst_port"] for f in flows["items"]} == {22, 80, 443}


def test_duplicate_upload_is_deduplicated(server, tmp_path):
    client, _ = server
    data = _pcap_bytes(tmp_path)
    first = _upload(client, data)
    second = _upload(client, data, name="again.pcap")
    assert (first.status_code, second.status_code) == (201, 200)
    assert first.json()["id"] == second.json()["id"]
    assert client.get(f"{API}/captures").json()["total"] == 1


def test_upload_rejects_non_captures_and_oversize(server):
    client, _ = server
    assert _upload(client, b"<html>not a capture</html>").status_code == 415
    assert _upload(client, b"").status_code == 400
    big = b"\xd4\xc3\xb2\xa1" + b"\x00" * 2_100_000
    assert _upload(client, big).status_code == 413
    stored = list((client.app.state.settings.captures_dir).iterdir())
    assert stored == []  # rejected uploads leave nothing behind


def test_filenames_are_display_only():
    assert safe_filename("../../etc/passwd") == "passwd"
    assert safe_filename("C:\\Users\\x\\evil<script>.pcap") == "evil_script_.pcap"
    assert safe_filename("...") == "capture"


def test_config_overrides_are_validated_and_applied(server, tmp_path):
    client, app = server
    cid = _upload(client, _pcap_bytes(tmp_path)).json()["id"]
    bad = client.post(f"{API}/captures/{cid}/analyses", json={"config": {"portscan": {"nope": 1}}})
    assert bad.status_code == 422
    assert "unknown keys" in bad.json()["detail"]
    analysis = _analyse(client, app, cid, {"portscan": {"enabled": False}, "trw": {"enabled": False}})
    assert analysis["status"] == "done"
    assert analysis["alert_count"] == 0
    assert analysis["config"]["portscan"]["enabled"] is False


def test_corrupt_capture_fails_the_job_cleanly(server):
    client, app = server
    hostile = (
        b"\xd4\xc3\xb2\xa1" + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1) + struct.pack("<IIII", 0, 0, 2**32 - 1, 60)
    )
    cid = _upload(client, hostile).json()["id"]
    analysis = _analyse(client, app, cid)
    assert analysis["status"] == "failed"
    assert "exceeds" in analysis["error"]
    assert "/" not in analysis["error"]  # no server paths leak to clients


def test_job_timeout_kills_the_worker(tmp_path):
    settings = ServerSettings(data_dir=tmp_path / "data", run_jobs=False, jobs=JobLimits(timeout_seconds=0.01))
    app = create_app(settings)
    with TestClient(app) as client:
        cid = _upload(client, _pcap_bytes(tmp_path)).json()["id"]
        analysis = _analyse(client, app, cid)
    assert analysis["status"] == "failed"
    assert "timed out" in analysis["error"]
    assert analysis["flow_count"] == 0


def test_cancel_queued_analysis_and_conflict(server, tmp_path):
    client, app = server
    cid = _upload(client, _pcap_bytes(tmp_path)).json()["id"]
    aid = client.post(f"{API}/captures/{cid}/analyses", json={}).json()["id"]
    assert client.post(f"{API}/analyses/{aid}/cancel").json()["status"] == "cancelled"
    assert client.post(f"{API}/analyses/{aid}/cancel").status_code == 409
    assert app.state.runner.run_pending() == 0


def test_delete_capture_cascades(server, tmp_path):
    client, app = server
    cid = _upload(client, _pcap_bytes(tmp_path)).json()["id"]
    _analyse(client, app, cid)
    assert client.delete(f"{API}/captures/{cid}").status_code == 204
    assert client.get(f"{API}/captures/{cid}").status_code == 404
    assert client.get(f"{API}/alerts").json()["total"] == 0
    assert not (app.state.settings.captures_dir / cid).exists()


def test_alert_filters_sorting_and_validation(server, tmp_path):
    client, app = server
    analysis = _analyse(client, app, _upload(client, _pcap_bytes(tmp_path, "arp_spoof_mitm")).json()["id"])
    base = {"analysis_id": analysis["id"]}
    total = client.get(f"{API}/alerts", params=base).json()["total"]
    high = client.get(f"{API}/alerts", params={**base, "severity": "HIGH"}).json()
    assert 0 < high["total"] < total
    assert all(a["severity"] == "HIGH" for a in high["items"])
    assert client.get(f"{API}/alerts", params={**base, "ip": "10.0.0.1"}).json()["total"] >= 1
    assert client.get(f"{API}/alerts", params={**base, "q": "100%_literal"}).json()["total"] == 0
    page = client.get(f"{API}/alerts", params={**base, "limit": 1, "offset": 1}).json()
    assert (len(page["items"]), page["total"]) == (1, total)
    assert client.get(f"{API}/alerts", params={"sort": "summary; DROP TABLE alerts"}).status_code == 400
    assert client.get(f"{API}/alerts", params={"limit": 5000}).status_code == 422
    assert client.get(f"{API}/alerts", params={"severity": "CRITICAL"}).status_code == 422


def test_export_alerts_native_and_ecs(server, tmp_path):
    client, app = server
    analysis = _analyse(client, app, _upload(client, _pcap_bytes(tmp_path)).json()["id"])
    native = client.get(f"{API}/analyses/{analysis['id']}/alerts.ndjson")
    assert native.headers["content-type"].startswith("application/x-ndjson")
    rows = [json.loads(line) for line in native.text.splitlines()]
    assert {r["rule_id"] for r in rows} == {"NG-SCAN-001", "NG-SCAN-002"}
    ecs = [
        json.loads(line)
        for line in client.get(
            f"{API}/analyses/{analysis['id']}/alerts.ndjson", params={"format": "ecs"}
        ).text.splitlines()
    ]
    assert ecs[0]["event"]["kind"] == "alert"
    assert ecs[0]["source"]["ip"] == "10.0.0.66"
    assert ecs[0]["threat"]["technique"]["id"] == ["T1046"]
    assert client.get(f"{API}/analyses/{analysis['id']}/alerts.ndjson", params={"format": "xml"}).status_code == 400


def test_rules_endpoint(server):
    client, _ = server
    rules = {r["rule_id"]: r for r in client.get(f"{API}/rules").json()}
    assert len(rules) == 11
    assert rules["NG-SYN-001"]["settings"]["min_attempts"] == 500


def test_security_headers(server):
    client, _ = server
    r = client.get(f"{API}/health")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["cache-control"] == "no-store"


def test_token_is_required_when_configured(tmp_path):
    settings = ServerSettings(data_dir=tmp_path / "d", token=TOKEN, run_jobs=False)
    with TestClient(create_app(settings)) as client:
        assert client.get(f"{API}/health").status_code == 200  # health stays open for probes
        assert client.get(f"{API}/captures").status_code == 401
        assert client.get(f"{API}/captures", headers={"Authorization": "Bearer wrong"}).status_code == 401
        ok = client.get(f"{API}/captures", headers={"Authorization": f"Bearer {TOKEN}"})
        assert ok.status_code == 200


def test_remote_bind_requires_a_token(tmp_path):
    with pytest.raises(SettingsError, match="refusing"):
        create_app(ServerSettings(data_dir=tmp_path, host="0.0.0.0"))
    with pytest.raises(SettingsError, match="at least"):
        create_app(ServerSettings(data_dir=tmp_path, token="short"))
    create_app(ServerSettings(data_dir=tmp_path, host="0.0.0.0", token=TOKEN))


def test_interrupted_jobs_are_recovered_on_start(tmp_path):
    settings = ServerSettings(data_dir=tmp_path / "data", run_jobs=False)
    app = create_app(settings)
    with TestClient(app) as client:
        cid = _upload(client, _pcap_bytes(tmp_path)).json()["id"]
        aid = client.post(f"{API}/captures/{cid}/analyses", json={}).json()["id"]
        assert app.state.store.claim_next()["id"] == aid  # a worker "dies" while running it
    store = app.state.store
    assert store.recover_interrupted() == (1, 0)
    assert store.get_analysis(aid)["status"] == "queued"
    assert store.claim_next()["id"] == aid
    assert store.recover_interrupted() == (0, 1)  # second interruption: give up
    analysis = store.get_analysis(aid)
    assert analysis["status"] == "failed"
    assert "interrupted" in analysis["error"]


def test_background_runner_processes_jobs(tmp_path):
    """The production path: the runner thread picks up the job by itself."""
    settings = ServerSettings(data_dir=tmp_path / "data")  # run_jobs=True
    app = create_app(settings)
    with TestClient(app) as client:
        cid = _upload(client, _pcap_bytes(tmp_path, "ping_sweep")).json()["id"]
        aid = client.post(f"{API}/captures/{cid}/analyses", json={}).json()["id"]
        deadline = time.monotonic() + 30
        while (status := client.get(f"{API}/analyses/{aid}").json()["status"]) in ("queued", "running"):
            assert time.monotonic() < deadline, "runner did not finish the job"
            time.sleep(0.05)
        assert status == "done"
        assert client.get(f"{API}/alerts", params={"analysis_id": aid, "rule_id": "NG-SWEEP-001"}).json()["total"] == 1


def test_stored_data_is_owner_only(server, tmp_path):
    client, app = server
    cid = _upload(client, _pcap_bytes(tmp_path)).json()["id"]
    settings = app.state.settings
    assert settings.data_dir.stat().st_mode & 0o777 == 0o700
    assert settings.db_path.stat().st_mode & 0o777 == 0o600
    assert (settings.captures_dir / cid).stat().st_mode & 0o777 == 0o600


# --- Phase 5 backend: profiles, summary, exports, dashboard ------------------------------


def test_profiles_crud_and_validation(server):
    client, _ = server
    created = client.post(
        f"{API}/profiles", json={"name": "strict scans", "config": {"portscan": {"min_distinct_ports": 5}}}
    )
    assert created.status_code == 201
    pid = created.json()["id"]
    assert client.post(f"{API}/profiles", json={"name": "strict scans"}).status_code == 400  # duplicate name
    bad = client.post(f"{API}/profiles", json={"name": "bad", "config": {"portscan": {"nope": 1}}})
    assert bad.status_code == 422
    assert client.post(f"{API}/profiles", json={"name": "<script>"}).status_code == 422  # name pattern
    updated = client.put(f"{API}/profiles/{pid}", json={"name": "strict", "config": {"trw": {"enabled": False}}})
    assert updated.json()["config"] == {"trw": {"enabled": False}}
    assert [p["name"] for p in client.get(f"{API}/profiles").json()] == ["strict"]
    assert client.put(f"{API}/profiles/nope", json={"name": "x"}).status_code == 404
    assert client.delete(f"{API}/profiles/{pid}").status_code == 204
    assert client.get(f"{API}/profiles/{pid}").status_code == 404


def test_analysis_with_profile_and_extra_overrides(server, tmp_path):
    client, app = server
    pid = client.post(
        f"{API}/profiles", json={"name": "no scan rules", "config": {"portscan": {"enabled": False}}}
    ).json()["id"]
    cid = _upload(client, _pcap_bytes(tmp_path)).json()["id"]
    r = client.post(f"{API}/captures/{cid}/analyses", json={"profile_id": pid, "config": {"trw": {"enabled": False}}})
    assert r.status_code == 202
    assert r.json()["profile_id"] == pid
    app.state.runner.run_pending()
    analysis = client.get(f"{API}/analyses/{r.json()['id']}").json()
    assert analysis["alert_count"] == 0  # profile disabled portscan, request disabled trw
    assert analysis["config"]["portscan"]["enabled"] is False
    missing = client.post(f"{API}/captures/{cid}/analyses", json={"profile_id": "nope"})
    assert missing.status_code == 404


def test_summary_counts_everything(server, tmp_path):
    client, app = server
    _analyse(client, app, _upload(client, _pcap_bytes(tmp_path)).json()["id"])
    s = client.get(f"{API}/summary").json()
    assert s["captures"] == 1
    assert s["analyses"]["done"] == 1
    assert s["alerts"]["HIGH"] == 2
    assert {r["rule_id"] for r in s["alerts_by_rule"]} == {"NG-SCAN-001", "NG-SCAN-002"}
    assert len(s["recent_alerts"]) == 2


def test_flows_csv_export(server, tmp_path):
    client, app = server
    analysis = _analyse(client, app, _upload(client, _pcap_bytes(tmp_path)).json()["id"])
    r = client.get(f"{API}/analyses/{analysis['id']}/flows.csv")
    assert r.headers["content-type"].startswith("text/csv")
    lines = r.text.splitlines()
    assert lines[0].startswith("proto,src_ip,src_port")
    assert len(lines) == 1001


def test_html_report_is_scriptless_and_requires_done(server, tmp_path):
    client, app = server
    cid = _upload(client, _pcap_bytes(tmp_path), name="<img src=x onerror=alert(1)>.pcap").json()["id"]
    aid = client.post(f"{API}/captures/{cid}/analyses", json={}).json()["id"]
    assert client.get(f"{API}/analyses/{aid}/report.html").status_code == 409  # still queued
    app.state.runner.run_pending()
    r = client.get(f"{API}/analyses/{aid}/report.html")
    assert r.status_code == 200
    assert "<script" not in r.text.lower()
    assert "onerror=" not in r.text  # the filename was sanitised and escaped
    assert "default-src 'none'" in r.headers["content-security-policy"]
    assert "NG-SCAN-001" in r.text


def test_dashboard_fallback_and_csp(server, tmp_path):
    client, _ = server
    r = client.get("/alerts/42")  # a client-side route
    assert r.status_code == 200
    assert "script-src 'self'" in r.headers["content-security-policy"]
    assert client.get("/api/v1/nope").status_code == 404


def test_dashboard_bundle_is_served(tmp_path):
    static = tmp_path / "static"
    (static / "assets").mkdir(parents=True)
    (static / "index.html").write_text("<!doctype html><div id=root></div>")
    (static / "assets" / "app.js").write_text("console.log(1)")
    settings = ServerSettings(data_dir=tmp_path / "data", run_jobs=False, static_dir=static)
    with TestClient(create_app(settings)) as client:
        assert "id=root" in client.get("/analyses/abc").text
        assert client.get("/assets/app.js").text == "console.log(1)"
        (static / "favicon.svg").write_text("<svg/>")
        assert client.get("/favicon.svg").text == "<svg/>"
        secret = tmp_path / "secret.txt"
        secret.write_text("do not serve")
        for attempt in ("/../secret.txt", "/%2e%2e/secret.txt", "/assets/../../secret.txt"):
            assert "do not serve" not in client.get(attempt).text


# --- Phase 7: profile TOML, incidents, confidence ------------------------------------------


def test_profile_export_import_round_trip(server):
    client, _ = server
    pid = client.post(
        f"{API}/profiles",
        json={
            "name": "lab tuning",
            "description": "for the UTM lab",
            "config": {"portscan": {"min_distinct_ports": 5}},
        },
    ).json()["id"]
    exported = client.get(f"{API}/profiles/{pid}/export.toml")
    assert exported.status_code == 200
    assert "min_distinct_ports = 5" in exported.text
    assert exported.text.startswith("# NetGuard rule profile: lab tuning")
    imported = client.post(f"{API}/profiles/import", params={"name": "copy"}, content=exported.text.encode())
    assert imported.status_code == 201
    assert imported.json()["config"] == {"portscan": {"min_distinct_ports": 5}}


def test_profile_import_validates(server):
    client, _ = server
    bad_toml = client.post(f"{API}/profiles/import", params={"name": "x"}, content=b"[portscan\n")
    assert bad_toml.status_code == 422
    unknown = client.post(f"{API}/profiles/import", params={"name": "x"}, content=b"[portscan]\nnope = 1\n")
    assert unknown.status_code == 422
    huge = client.post(f"{API}/profiles/import", params={"name": "x"}, content=b"#" * 70_000)
    assert huge.status_code == 413
    assert client.post(f"{API}/profiles/import", params={"name": "<b>"}, content=b"").status_code == 422


def test_incidents_and_confidence_in_the_api(server, tmp_path):
    client, app = server
    analysis = _analyse(client, app, _upload(client, _pcap_bytes(tmp_path)).json()["id"])
    incidents = client.get(f"{API}/analyses/{analysis['id']}/incidents").json()
    assert len(incidents) == 1
    assert incidents[0]["rules"] == ["NG-SCAN-001", "NG-SCAN-002"]
    alert = client.get(f"{API}/alerts", params={"analysis_id": analysis["id"]}).json()["items"][0]
    assert alert["confidence"]["level"] == "high"
    assert alert["confidence"]["factors"]
    assert client.get(f"{API}/analyses/nope/incidents").status_code == 404
