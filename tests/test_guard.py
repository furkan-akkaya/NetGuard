"""Localhost-API attacks from a malicious web page (THREAT_MODEL.md): rebinding, cross-site writes, big bodies."""

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from netguard.lab.scenarios import get
from netguard.lab.synth import write_pcap
from netguard.web.app import create_app
from netguard.web.settings import ServerSettings

API = "/api/v1"
EVIL = "https://attacker.example"


@pytest.fixture
def pcap(tmp_path):
    path = tmp_path / "x.pcap"
    write_pcap(path, get("xmas_scan").build())
    return path.read_bytes()


def _client(tmp_path, **kw):
    return TestClient(
        create_app(ServerSettings(data_dir=tmp_path / "d", run_jobs=False, **kw)), base_url="http://localhost"
    )


def test_dns_rebinding_host_is_refused(tmp_path):
    with _client(tmp_path) as c:
        assert c.get(f"{API}/captures", headers={"Host": "attacker.example:8000"}).status_code == 421
        assert c.get("/", headers={"Host": "attacker.example"}).status_code == 421  # the dashboard too
        for ok in ("localhost:8000", "127.0.0.1:8000", "[::1]:8000"):
            assert c.get(f"{API}/health", headers={"Host": ok}).status_code == 200


def test_allowed_host_option(tmp_path):
    with _client(tmp_path, allowed_hosts=["netguard.lab"]) as c:
        assert c.get(f"{API}/health", headers={"Host": "netguard.lab"}).status_code == 200
        assert c.get(f"{API}/health", headers={"Host": "other.lab"}).status_code == 421


def test_cross_origin_writes_are_refused(tmp_path, pcap):
    with _client(tmp_path) as c:
        attack = {"Origin": EVIL, "Content-Type": "application/octet-stream"}
        assert c.post(f"{API}/captures", content=pcap, headers=attack).status_code == 403
        toml = {"Origin": EVIL, "Content-Type": "application/toml"}
        assert c.post(f"{API}/profiles/import?name=x", content=b"", headers=toml).status_code == 403
        assert c.delete(f"{API}/captures/x", headers={"Origin": EVIL}).status_code == 403
        same = {"Origin": "http://localhost", "Content-Type": "application/octet-stream"}
        assert c.post(f"{API}/captures", content=pcap, headers=same).status_code == 201
        assert c.get(f"{API}/captures", headers={"Origin": EVIL}).status_code == 200  # reads cannot be sent cross-site


def test_simple_request_content_types_are_refused(tmp_path, pcap):
    """text/plain is what a cross-site form or fetch can send without a CORS preflight."""
    with _client(tmp_path) as c:
        assert c.post(f"{API}/captures", content=pcap, headers={"Content-Type": "text/plain"}).status_code == 415
        r = c.post(f"{API}/profiles/import?name=x", content=b"", headers={"Content-Type": "text/plain"})
        assert r.status_code == 415


def test_body_size_limit_outside_the_upload(tmp_path):
    big = b'{"name": "x", "config": {"a": "' + b"A" * 2_000_000 + b'"}}'
    with _client(tmp_path) as c:
        r = c.post(f"{API}/profiles", content=big, headers={"Content-Type": "application/json"})
        assert r.status_code == 413

        def chunks():  # no Content-Length: the limit is counted while reading
            for _ in range(40):
                yield b"A" * 65536

        r = c.post(f"{API}/profiles", content=chunks(), headers={"Content-Type": "application/json"})
        assert r.status_code == 413


def test_storage_quota_and_queue_limit(tmp_path, pcap):
    with _client(tmp_path, max_storage_bytes=len(pcap) + 10, max_pending_analyses=1) as c:
        up = {"Content-Type": "application/octet-stream"}
        cid = c.post(f"{API}/captures", content=pcap, headers=up).json()["id"]
        other = pcap + b"\x00" * 16  # a different file: the quota is used up
        assert c.post(f"{API}/captures", content=other, headers=up).status_code in (413, 507)
        assert c.post(f"{API}/captures/{cid}/analyses", json={}).status_code == 202
        assert c.post(f"{API}/captures/{cid}/analyses", json={}).status_code == 429
