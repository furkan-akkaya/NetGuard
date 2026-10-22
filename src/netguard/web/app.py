"""The NetGuard REST API, version 1 (``/api/v1``). See ADR-0008.

Every route except ``/api/v1/health`` requires the bearer token when one is
configured. All timestamps are ISO 8601 UTC strings. List endpoints return
``{items, total, limit, offset}`` and accept ``limit`` (1-1000), ``offset``
and ``sort`` (a field name, ``-`` prefix for descending).
"""

from __future__ import annotations

import csv
import hashlib
import hmac
import io
import json
import logging
import os
import re
import uuid
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from dataclasses import fields
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from netguard import __version__
from netguard.config import ConfigError, config_to_mapping, merge_config
from netguard.detectors import DETECTORS
from netguard.events import FORMATS, export
from netguard.formats import PCAP_MAGICS, PCAPNG_MAGIC
from netguard.jobs import JobRunner
from netguard.models import iso_ts
from netguard.output import FLOW_FIELDS
from netguard.report import render_report
from netguard.store import SCHEMA_VERSION, Store, StoreError
from netguard.store import Page as StorePage
from netguard.web import schemas
from netguard.web.settings import ServerSettings

log = logging.getLogger("netguard.web")
STATIC_DIR = Path(__file__).parent / "static"
#: The dashboard is a static bundle: scripts and styles only from our origin,
#: no inline script, no framing, no plugins.
DASHBOARD_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
    "font-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
)
NO_DASHBOARD = """<!doctype html><meta charset="utf-8"><title>NetGuard</title>
<p>The NetGuard API is running (<a href="/api/v1/docs">API docs</a>), but the dashboard bundle is not built.
Build it with <code>pnpm --dir frontend install &amp;&amp; pnpm --dir frontend build</code> and restart.</p>"""
API = "/api/v1"
_FILENAME_SAFE = re.compile(r"[^A-Za-z0-9._ ()-]")

Limit = Annotated[int, Query(ge=1, le=1000)]
Offset = Annotated[int, Query(ge=0)]


def _iso(ts: float | None) -> str | None:
    return iso_ts(ts) if ts is not None else None


def _capture(row: dict[str, Any]) -> dict[str, Any]:
    return {**row, "created_at": _iso(row["created_at"])}


def _analysis(row: dict[str, Any], full: bool = True) -> dict[str, Any]:
    out = {**row, **{k: _iso(row[k]) for k in ("created_at", "started_at", "finished_at")}}
    if not full:
        for key in ("config", "capture_info", "stats"):
            out.pop(key, None)
    return out


def _page(page: StorePage, convert: Any = None) -> dict[str, Any]:
    items = [convert(i) for i in page.items] if convert else page.items
    return {"items": items, "total": page.total, "limit": page.limit, "offset": page.offset}


def safe_filename(name: str) -> str:
    """Display name only: never used as a path. Basename, safe characters, at most 128 chars."""
    base = name.replace("\\", "/").rsplit("/", 1)[-1]
    cleaned = _FILENAME_SAFE.sub("_", base).strip(" .")
    return cleaned[:128] or "capture"


def create_app(settings: ServerSettings) -> FastAPI:
    settings.validate()
    store = Store(settings.db_path)
    runner = JobRunner(store, settings.captures_dir, settings.jobs)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        # Captures may hold credentials and personal data: owner-only access.
        settings.data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        settings.captures_dir.mkdir(mode=0o700, exist_ok=True)
        store.migrate()
        settings.db_path.chmod(0o600)
        if settings.run_jobs:
            runner.start()
        yield
        if settings.run_jobs:
            runner.stop()

    app = FastAPI(
        title="NetGuard API",
        version=__version__,
        description="Network intrusion detection and traffic analysis. Upload a capture, analyse it, "
        "and search the resulting alerts and flows.",
        lifespan=lifespan,
        docs_url=f"{API}/docs",
        redoc_url=None,
        openapi_url=f"{API}/openapi.json",
    )
    app.state.store = store
    app.state.runner = runner
    app.state.settings = settings

    @app.middleware("http")
    async def security_headers(request: Request, call_next: Any) -> Response:
        response: Response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        if request.url.path.startswith(API):
            response.headers.setdefault("Cache-Control", "no-store")
        else:
            response.headers.setdefault("Content-Security-Policy", DASHBOARD_CSP)
        return response

    @app.exception_handler(StoreError)
    async def store_error(_: Request, exc: StoreError) -> JSONResponse:
        return JSONResponse(status_code=400, content={"detail": str(exc)})

    def require_token(authorization: Annotated[str | None, Header()] = None) -> None:
        if not settings.token:
            return
        expected = f"Bearer {settings.token}".encode()
        if authorization is None or not hmac.compare_digest(authorization.encode(), expected):
            raise HTTPException(
                status_code=401, detail="missing or invalid API token", headers={"WWW-Authenticate": "Bearer"}
            )

    auth = [Depends(require_token)]

    # ------------------------------------------------------------- service

    @app.get(f"{API}/health", response_model=schemas.Health, tags=["service"])
    def health() -> dict[str, Any]:
        return {"status": "ok", "version": __version__, "schema_version": SCHEMA_VERSION}

    @app.get(f"{API}/rules", response_model=list[schemas.Rule], dependencies=auth, tags=["rules"])
    def rules() -> list[dict[str, Any]]:
        base = settings.analysis_config
        out = []
        for det in DETECTORS:
            section = getattr(base, det.name)
            for rule in det.rules:
                out.append(
                    {
                        "rule_id": rule.rule_id,
                        "detector": det.name,
                        "title": rule.title,
                        "technique": rule.technique.id if rule.technique else None,
                        "enabled": section.enabled,
                        "settings": {f.name: getattr(section, f.name) for f in fields(section)},
                        "doc": f"docs/rules/{rule.rule_id}.md",
                    }
                )
        return out

    @app.get(f"{API}/summary", response_model=schemas.Summary, dependencies=auth, tags=["service"])
    def summary() -> dict[str, Any]:
        data = store.summary()
        data["recent_analyses"] = [_analysis(a, full=False) for a in data["recent_analyses"]]
        return data

    # ------------------------------------------------------------ profiles

    def _profile(row: dict[str, Any]) -> dict[str, Any]:
        return {**row, "created_at": _iso(row["created_at"]), "updated_at": _iso(row["updated_at"])}

    def _validated(body: schemas.ProfileIn) -> dict[str, Any]:
        try:
            merge_config(settings.analysis_config, body.config)
        except ConfigError as exc:
            raise HTTPException(status_code=422, detail=f"invalid configuration: {exc}") from exc
        return body.config

    @app.get(f"{API}/profiles", response_model=list[schemas.Profile], dependencies=auth, tags=["rules"])
    def list_profiles() -> list[dict[str, Any]]:
        return [_profile(p) for p in store.list_profiles()]

    @app.post(f"{API}/profiles", response_model=schemas.Profile, status_code=201, dependencies=auth, tags=["rules"])
    def create_profile(body: schemas.ProfileIn) -> dict[str, Any]:
        return _profile(store.save_profile(body.name, body.description, _validated(body)))

    @app.get(f"{API}/profiles/{{profile_id}}", response_model=schemas.Profile, dependencies=auth, tags=["rules"])
    def get_profile(profile_id: str) -> dict[str, Any]:
        row = store.get_profile(profile_id)
        if row is None:
            raise HTTPException(status_code=404, detail="profile not found")
        return _profile(row)

    @app.put(f"{API}/profiles/{{profile_id}}", response_model=schemas.Profile, dependencies=auth, tags=["rules"])
    def update_profile(profile_id: str, body: schemas.ProfileIn) -> dict[str, Any]:
        try:
            return _profile(store.save_profile(body.name, body.description, _validated(body), profile_id))
        except LookupError as exc:
            raise HTTPException(status_code=404, detail="profile not found") from exc

    @app.delete(f"{API}/profiles/{{profile_id}}", status_code=204, dependencies=auth, tags=["rules"])
    def delete_profile(profile_id: str) -> Response:
        if not store.delete_profile(profile_id):
            raise HTTPException(status_code=404, detail="profile not found")
        return Response(status_code=204)

    # ------------------------------------------------------------ captures

    @app.post(
        f"{API}/captures",
        response_model=schemas.Capture,
        status_code=201,
        dependencies=auth,
        tags=["captures"],
        summary="Upload a pcap/pcapng file as the raw request body",
        responses={200: {"description": "Identical capture already stored"}, 413: {}, 415: {}},
    )
    async def upload_capture(
        request: Request, response: Response, filename: Annotated[str, Query(max_length=255)] = "capture.pcap"
    ) -> dict[str, Any]:
        limit = settings.max_upload_bytes
        declared = request.headers.get("content-length")
        if declared is not None and declared.isdigit() and int(declared) > limit:
            raise HTTPException(status_code=413, detail=f"capture larger than the {limit} byte limit")
        tmp = settings.captures_dir / f".upload-{uuid.uuid4().hex}"
        digest = hashlib.sha256()
        size = 0
        head = b""
        try:
            with os.fdopen(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as fh:
                async for chunk in request.stream():
                    size += len(chunk)
                    if size > limit:
                        raise HTTPException(status_code=413, detail=f"capture larger than the {limit} byte limit")
                    if len(head) < 4:
                        head += chunk[: 4 - len(head)]
                    digest.update(chunk)
                    await run_in_threadpool(fh.write, chunk)
            if size == 0:
                raise HTTPException(status_code=400, detail="empty upload: send the capture as the request body")
            if head in PCAP_MAGICS:
                fmt = "pcap"
            elif head == PCAPNG_MAGIC:
                fmt = "pcapng"
            else:
                raise HTTPException(status_code=415, detail="not a pcap or pcapng file")
            row, created = store.add_capture(safe_filename(filename), digest.hexdigest(), size, fmt)
            if created:
                os.replace(tmp, settings.captures_dir / row["id"])
            else:
                response.status_code = 200
            return _capture(row)
        finally:
            tmp.unlink(missing_ok=True)

    @app.get(f"{API}/captures", response_model=schemas.Page[schemas.Capture], dependencies=auth, tags=["captures"])
    def list_captures(limit: Limit = 50, offset: Offset = 0, sort: str = "-created_at") -> dict[str, Any]:
        return _page(store.list_captures(limit, offset, sort), _capture)

    @app.get(f"{API}/captures/{{capture_id}}", response_model=schemas.Capture, dependencies=auth, tags=["captures"])
    def get_capture(capture_id: str) -> dict[str, Any]:
        row = store.get_capture(capture_id)
        if row is None:
            raise HTTPException(status_code=404, detail="capture not found")
        return _capture(row)

    @app.delete(f"{API}/captures/{{capture_id}}", status_code=204, dependencies=auth, tags=["captures"])
    def delete_capture(capture_id: str) -> Response:
        if not store.delete_capture(capture_id):
            raise HTTPException(status_code=404, detail="capture not found")
        (settings.captures_dir / capture_id).unlink(missing_ok=True)
        return Response(status_code=204)

    # ------------------------------------------------------------ analyses

    @app.post(
        f"{API}/captures/{{capture_id}}/analyses",
        response_model=schemas.Analysis,
        status_code=202,
        dependencies=auth,
        tags=["analyses"],
        summary="Queue an analysis of a stored capture, optionally with configuration overrides",
    )
    def create_analysis(capture_id: str, body: schemas.AnalysisRequest | None = None) -> dict[str, Any]:
        if store.get_capture(capture_id) is None:
            raise HTTPException(status_code=404, detail="capture not found")
        base = settings.analysis_config
        profile_id = body.profile_id if body else None
        try:
            if profile_id is not None:
                profile = store.get_profile(profile_id)
                if profile is None:
                    raise HTTPException(status_code=404, detail="profile not found")
                base = merge_config(base, profile["config"])
            config = merge_config(base, body.config if body else {})
        except ConfigError as exc:
            raise HTTPException(status_code=422, detail=f"invalid configuration: {exc}") from exc
        row = store.create_analysis(capture_id, config_to_mapping(config), __version__, profile_id)
        runner.wake()
        return _analysis(row)

    @app.get(
        f"{API}/analyses", response_model=schemas.Page[schemas.AnalysisSummary], dependencies=auth, tags=["analyses"]
    )
    def list_analyses(
        capture_id: str | None = None,
        status: schemas.Status | None = None,
        limit: Limit = 50,
        offset: Offset = 0,
        sort: str = "-created_at",
    ) -> dict[str, Any]:
        page = store.list_analyses(capture_id, status, limit, offset, sort)
        return _page(page, lambda r: _analysis(r, full=False))

    @app.get(f"{API}/analyses/{{analysis_id}}", response_model=schemas.Analysis, dependencies=auth, tags=["analyses"])
    def get_analysis(analysis_id: str) -> dict[str, Any]:
        row = store.get_analysis(analysis_id)
        if row is None:
            raise HTTPException(status_code=404, detail="analysis not found")
        return _analysis(row)

    @app.post(
        f"{API}/analyses/{{analysis_id}}/cancel",
        response_model=schemas.Analysis,
        dependencies=auth,
        tags=["analyses"],
        responses={409: {"description": "Analysis already finished"}},
    )
    def cancel_analysis(analysis_id: str) -> dict[str, Any]:
        if store.get_analysis(analysis_id) is None:
            raise HTTPException(status_code=404, detail="analysis not found")
        if not store.cancel_analysis(analysis_id):
            raise HTTPException(status_code=409, detail="analysis already finished")
        row = store.get_analysis(analysis_id)
        assert row is not None
        return _analysis(row)

    @app.get(
        f"{API}/analyses/{{analysis_id}}/flows",
        response_model=schemas.Page[schemas.FlowOut],
        dependencies=auth,
        tags=["flows"],
    )
    def list_flows(
        analysis_id: str,
        proto: str | None = None,
        state: str | None = None,
        ip: str | None = None,
        port: Annotated[int | None, Query(ge=0, le=65535)] = None,
        limit: Limit = 50,
        offset: Offset = 0,
        sort: str = "first_seen",
    ) -> dict[str, Any]:
        if store.get_analysis(analysis_id) is None:
            raise HTTPException(status_code=404, detail="analysis not found")
        return _page(store.search_flows(analysis_id, proto, state, ip, port, limit, offset, sort))

    @app.get(
        f"{API}/analyses/{{analysis_id}}/alerts.ndjson",
        dependencies=auth,
        tags=["alerts"],
        summary="Export all alerts of an analysis as newline-delimited JSON (native or ECS)",
        response_class=StreamingResponse,
    )
    def export_alerts(analysis_id: str, format: str = "netguard") -> StreamingResponse:
        if format not in FORMATS:
            raise HTTPException(status_code=400, detail=f"format must be one of: {', '.join(FORMATS)}")
        if store.get_analysis(analysis_id) is None:
            raise HTTPException(status_code=404, detail="analysis not found")

        def lines() -> Iterator[str]:
            for alert in store.iter_alerts(analysis_id):
                yield json.dumps(export(alert, format)) + "\n"

        return StreamingResponse(
            lines(),
            media_type="application/x-ndjson",
            headers={"Content-Disposition": f'attachment; filename="netguard-{analysis_id}-{format}.ndjson"'},
        )

    @app.get(
        f"{API}/analyses/{{analysis_id}}/flows.csv",
        dependencies=auth,
        tags=["flows"],
        summary="Export the stored flows of an analysis as CSV",
        response_class=StreamingResponse,
    )
    def export_flows(analysis_id: str) -> StreamingResponse:
        if store.get_analysis(analysis_id) is None:
            raise HTTPException(status_code=404, detail="analysis not found")

        def rows() -> Iterator[str]:
            buf = io.StringIO()
            writer = csv.DictWriter(buf, fieldnames=FLOW_FIELDS, extrasaction="ignore", lineterminator="\n")
            writer.writeheader()
            for flow in store.iter_flows(analysis_id):
                writer.writerow(flow)
                if buf.tell() > 65536:
                    yield buf.getvalue()
                    buf.seek(0)
                    buf.truncate()
            yield buf.getvalue()

        return StreamingResponse(
            rows(),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="netguard-{analysis_id}-flows.csv"'},
        )

    @app.get(
        f"{API}/analyses/{{analysis_id}}/report.html",
        dependencies=auth,
        tags=["analyses"],
        summary="A single-file HTML report of a finished analysis (no scripts, printable)",
        response_class=HTMLResponse,
    )
    def report(analysis_id: str) -> HTMLResponse:
        analysis = store.get_analysis(analysis_id)
        if analysis is None:
            raise HTTPException(status_code=404, detail="analysis not found")
        if analysis["status"] != "done":
            raise HTTPException(status_code=409, detail=f"analysis is {analysis['status']}, not done")
        capture = store.get_capture(analysis["capture_id"])
        name = capture["filename"] if capture else analysis["capture_id"]
        meta = {
            "Analysis": analysis_id,
            "Capture SHA-256": capture["sha256"] if capture else "",
            "Analysed": _iso(analysis["finished_at"]),
            "NetGuard": analysis["netguard_version"],
        }
        page = render_report(
            analysis["stats"], list(store.iter_alerts(analysis_id)), name, analysis["capture_info"], meta
        )
        return HTMLResponse(page, headers={"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'"})

    # -------------------------------------------------------------- alerts

    @app.get(f"{API}/alerts", response_model=schemas.Page[schemas.AlertOut], dependencies=auth, tags=["alerts"])
    def search_alerts(
        analysis_id: str | None = None,
        rule_id: str | None = None,
        severity: schemas.SeverityName | None = None,
        min_severity: schemas.SeverityName | None = None,
        ip: str | None = None,
        q: Annotated[str | None, Query(max_length=200, description="Text search in title and summary")] = None,
        since: Annotated[float | None, Query(description="Unix time: alerts active at or after")] = None,
        until: Annotated[float | None, Query(description="Unix time: alerts starting at or before")] = None,
        limit: Limit = 50,
        offset: Offset = 0,
        sort: str = "-first_seen",
    ) -> dict[str, Any]:
        page = store.search_alerts(
            analysis_id, rule_id, severity, min_severity, ip, q, since, until, limit, offset, sort
        )
        return _page(page)

    @app.get(f"{API}/alerts/{{alert_id}}", response_model=schemas.AlertOut, dependencies=auth, tags=["alerts"])
    def get_alert(alert_id: int) -> dict[str, Any]:
        row = store.get_alert(alert_id)
        if row is None:
            raise HTTPException(status_code=404, detail="alert not found")
        return row

    # ----------------------------------------------------------- dashboard

    static_dir = settings.static_dir or STATIC_DIR
    if (static_dir / "assets").is_dir():
        app.mount("/assets", StaticFiles(directory=static_dir / "assets"), name="assets")

    @app.get("/{path:path}", include_in_schema=False)
    def dashboard(path: str) -> Response:
        # Client-side routes all serve index.html; unknown /api paths stay 404.
        if path.startswith("api/"):
            raise HTTPException(status_code=404, detail="not found")
        index = static_dir / "index.html"
        if not index.is_file():
            return HTMLResponse(NO_DASHBOARD)
        return FileResponse(index, headers={"Cache-Control": "no-cache"})

    return app
