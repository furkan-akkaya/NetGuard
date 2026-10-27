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


def test_concurrent_uploads_cannot_exceed_the_quota(tmp_path):
    # Two 400-byte uploads against a 500-byte quota, both mid-stream at the same time.
    import asyncio

    import httpx2 as httpx

    app = create_app(ServerSettings(data_dir=tmp_path / "d", run_jobs=False, max_storage_bytes=500))

    async def race() -> tuple[list[int], int]:
        started = 0
        gate = asyncio.Event()

        async def body(marker: bytes):
            nonlocal started
            yield b"\xd4\xc3\xb2\xa1" + marker * 96
            started += 1
            if started == 2:
                gate.set()
            await asyncio.wait_for(gate.wait(), 5)
            yield marker * 300

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://localhost") as ac:
            responses = await asyncio.gather(
                *[
                    ac.post(f"{API}/captures", content=body(m), headers={"Content-Type": "application/octet-stream"})
                    for m in (b"A", b"B")
                ]
            )
            listed = (await ac.get(f"{API}/captures")).json()
        return sorted(r.status_code for r in responses), sum(row["size_bytes"] for row in listed["items"])

    with TestClient(app, base_url="http://localhost"):
        statuses, stored = asyncio.run(race())
    assert statuses == [201, 413]
    assert stored == 400
    assert app.state.quota.reserved == 0


def test_aborted_upload_releases_its_reservation(tmp_path):
    import asyncio

    import httpx2 as httpx

    app = create_app(ServerSettings(data_dir=tmp_path / "d", run_jobs=False, max_storage_bytes=500))

    async def abort() -> None:
        async def body():
            yield b"\xd4\xc3\xb2\xa1" + b"A" * 296
            raise ConnectionError("client went away")

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://localhost") as ac:
            with pytest.raises(Exception):  # noqa: B017 - the transport may wrap the client error
                await ac.post(f"{API}/captures", content=body(), headers={"Content-Type": "application/octet-stream"})

    with TestClient(app, base_url="http://localhost") as c:
        asyncio.run(abort())
        assert app.state.quota.reserved == 0
        full = b"\xd4\xc3\xb2\xa1" + b"C" * 496  # the whole quota is available again
        up = {"Content-Type": "application/octet-stream"}
        assert c.post(f"{API}/captures", content=full, headers=up).status_code == 201


def test_origin_must_match_scheme_host_and_port(tmp_path, pcap):
    # The test client sends Host: localhost over http, i.e. origin http://localhost(:80).
    with _client(tmp_path) as c:
        cid = c.post(f"{API}/captures", content=pcap, headers={"Content-Type": "application/octet-stream"}).json()["id"]
        refused = [
            "http://localhost:9999",  # same host, another port (another local service)
            "https://localhost",  # another scheme
            "null",  # sandboxed frames, file:// pages
            "http://",  # malformed
            "http://localhost:99999",  # invalid port
            "localhost",  # no scheme
        ]
        for origin in refused:
            r = c.post(f"{API}/profiles", json={"name": "x", "config": {}}, headers={"Origin": origin})
            assert r.status_code == 403, origin
            # A body-less POST that starts an analysis is a write too.
            assert c.post(f"{API}/captures/{cid}/analyses", headers={"Origin": origin}).status_code == 403, origin
        for i, origin in enumerate(("http://localhost", "http://localhost:80", "HTTP://LOCALHOST")):
            r = c.post(f"{API}/profiles", json={"name": f"same{i}", "config": {}}, headers={"Origin": origin})
            assert r.status_code == 201, origin


def test_reverse_proxy_origin_must_be_allowed_explicitly(tmp_path):
    # TLS proxy: the browser's origin is https://netguard.lab, NetGuard sees http with Host netguard.lab.
    proxied = {"Host": "netguard.lab", "Origin": "https://netguard.lab"}
    body = {"name": "p", "config": {}}
    with _client(tmp_path, allowed_hosts=["netguard.lab"]) as c:
        assert c.post(f"{API}/profiles", json=body, headers=proxied).status_code == 403
    with _client(tmp_path / "2", allowed_hosts=["netguard.lab"], allowed_origins=["https://netguard.lab"]) as c:
        assert c.post(f"{API}/profiles", json=body, headers=proxied).status_code == 201
        other_port = {**proxied, "Origin": "https://netguard.lab:8443"}
        assert c.post(f"{API}/profiles", json=body, headers=other_port).status_code == 403


def test_allowed_origins_are_validated(tmp_path):
    from netguard.web.settings import SettingsError

    for bad in ("netguard.lab", "https://netguard.lab/path", "ftp://netguard.lab", "null"):
        with pytest.raises(SettingsError):
            ServerSettings(data_dir=tmp_path, allowed_origins=[bad]).validate()
