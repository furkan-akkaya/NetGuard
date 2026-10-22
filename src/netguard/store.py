"""SQLite persistence for captures, analysis jobs, alerts and flows (ADR-0008).

One database file, WAL mode (the API reads while a worker writes), foreign
keys on, every statement parameterised. Connections are short-lived and
opened per operation: SQLite connections are cheap, and this keeps the store
safe to use from FastAPI's thread pool and from worker processes alike.

Search parameters arrive from HTTP clients, so filters are always bound
parameters and sort keys are looked up in per-table allowlists; no client
string is ever formatted into SQL.
"""

from __future__ import annotations

import json
import sqlite3
import time
import uuid
from collections.abc import Iterable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from netguard.flows import Flow
from netguard.models import Alert, iso_ts

#: Ordered migrations; index + 1 is the schema version after applying it.
MIGRATIONS: tuple[str, ...] = (
    """
    CREATE TABLE captures (
        id          TEXT PRIMARY KEY,
        filename    TEXT NOT NULL,
        sha256      TEXT NOT NULL UNIQUE,
        size_bytes  INTEGER NOT NULL,
        format      TEXT NOT NULL,
        created_at  REAL NOT NULL
    );
    CREATE TABLE analyses (
        id               TEXT PRIMARY KEY,
        capture_id       TEXT NOT NULL REFERENCES captures(id) ON DELETE CASCADE,
        status           TEXT NOT NULL
                         CHECK (status IN ('queued', 'running', 'done', 'failed', 'cancelled')),
        config           TEXT NOT NULL,
        created_at       REAL NOT NULL,
        started_at       REAL,
        finished_at      REAL,
        error            TEXT,
        attempts         INTEGER NOT NULL DEFAULT 0,
        netguard_version TEXT NOT NULL,
        capture_info     TEXT,
        stats            TEXT,
        alert_count      INTEGER NOT NULL DEFAULT 0,
        flow_count       INTEGER NOT NULL DEFAULT 0,
        flows_truncated  INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX analyses_status ON analyses(status, created_at);
    CREATE INDEX analyses_capture ON analyses(capture_id);
    CREATE TABLE alerts (
        id          INTEGER PRIMARY KEY,
        analysis_id TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
        alert_id    TEXT NOT NULL,
        rule_id     TEXT NOT NULL,
        detector    TEXT NOT NULL,
        severity    INTEGER NOT NULL,
        title       TEXT NOT NULL,
        src         TEXT,
        dst         TEXT,
        first_seen  REAL NOT NULL,
        last_seen   REAL NOT NULL,
        technique   TEXT,
        summary     TEXT NOT NULL,
        doc         TEXT NOT NULL
    );
    CREATE INDEX alerts_analysis ON alerts(analysis_id, first_seen);
    CREATE INDEX alerts_rule ON alerts(rule_id, first_seen);
    CREATE INDEX alerts_severity ON alerts(severity, first_seen);
    CREATE INDEX alerts_src ON alerts(src);
    CREATE INDEX alerts_dst ON alerts(dst);
    CREATE TABLE flows (
        id                 INTEGER PRIMARY KEY,
        analysis_id        TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
        proto              TEXT NOT NULL,
        src_ip             TEXT NOT NULL,
        src_port           INTEGER NOT NULL,
        dst_ip             TEXT NOT NULL,
        dst_port           INTEGER NOT NULL,
        first_seen         REAL NOT NULL,
        last_seen          REAL NOT NULL,
        duration           REAL NOT NULL,
        state              TEXT NOT NULL,
        history            TEXT NOT NULL,
        orig_packets       INTEGER NOT NULL,
        orig_bytes         INTEGER NOT NULL,
        orig_payload_bytes INTEGER NOT NULL,
        resp_packets       INTEGER NOT NULL,
        resp_bytes         INTEGER NOT NULL,
        resp_payload_bytes INTEGER NOT NULL,
        retransmissions    INTEGER NOT NULL,
        seq_gaps           INTEGER NOT NULL,
        end_reason         TEXT NOT NULL
    );
    CREATE INDEX flows_analysis ON flows(analysis_id, first_seen);
    CREATE INDEX flows_src ON flows(analysis_id, src_ip);
    CREATE INDEX flows_dst ON flows(analysis_id, dst_ip);
    CREATE INDEX flows_state ON flows(analysis_id, state);
    CREATE INDEX flows_port ON flows(analysis_id, dst_port);
    """,
)
SCHEMA_VERSION = len(MIGRATIONS)

STATUSES = ("queued", "running", "done", "failed", "cancelled")
FINAL_STATUSES = frozenset({"done", "failed", "cancelled"})
MAX_PAGE = 1000
SEVERITIES = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}

_FLOW_COLUMNS = (
    "proto",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "first_seen",
    "last_seen",
    "duration",
    "state",
    "history",
    "orig_packets",
    "orig_bytes",
    "orig_payload_bytes",
    "resp_packets",
    "resp_bytes",
    "resp_payload_bytes",
    "retransmissions",
    "seq_gaps",
    "end_reason",
)
_ALERT_SORTS = {
    "first_seen": "first_seen",
    "last_seen": "last_seen",
    "severity": "severity",
    "rule_id": "rule_id",
    "src": "src",
    "dst": "dst",
}
_FLOW_SORTS = {
    "first_seen": "first_seen",
    "duration": "duration",
    "bytes": "(orig_bytes + resp_bytes)",
    "packets": "(orig_packets + resp_packets)",
    "src_ip": "src_ip",
    "dst_ip": "dst_ip",
    "dst_port": "dst_port",
}
_ANALYSIS_SORTS = {"created_at": "created_at", "finished_at": "finished_at", "alert_count": "alert_count"}
_CAPTURE_SORTS = {"created_at": "created_at", "size_bytes": "size_bytes", "filename": "filename"}


class StoreError(ValueError):
    """A client-side problem with a query (bad sort key, bad page size)."""


@dataclass
class Page:
    items: list[dict[str, Any]]
    total: int
    limit: int
    offset: int


def new_id() -> str:
    return uuid.uuid4().hex


def _order(sort: str, allowed: dict[str, str]) -> str:
    desc = sort.startswith("-")
    key = sort.lstrip("-")
    if key not in allowed:
        raise StoreError(f"cannot sort by {key!r}; allowed: {', '.join(sorted(allowed))}")
    # The column expression comes from the allowlist, never from the client.
    return f"{allowed[key]} {'DESC' if desc else 'ASC'}, id ASC"


def _page_bounds(limit: int, offset: int) -> None:
    if not 1 <= limit <= MAX_PAGE:
        raise StoreError(f"limit must be between 1 and {MAX_PAGE}")
    if offset < 0:
        raise StoreError("offset must be >= 0")


def _like(text: str) -> str:
    """A LIKE pattern matching ``text`` literally (``%`` and ``_`` escaped)."""
    return "%" + text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


class Store:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    # ------------------------------------------------------------- plumbing

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=10.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA busy_timeout = 10000")
        try:
            yield conn
        finally:
            conn.close()

    @contextmanager
    def transaction(self, immediate: bool = False) -> Iterator[sqlite3.Connection]:
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
            try:
                yield conn
            except BaseException:
                conn.execute("ROLLBACK")
                raise
            conn.execute("COMMIT")

    def migrate(self) -> int:
        """Create or upgrade the schema. Returns the schema version."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as conn:
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        with self.transaction(immediate=True) as conn:
            row = conn.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()
            current = int(row["value"]) if row else 0
            if current > SCHEMA_VERSION:
                raise RuntimeError(
                    f"database schema {current} is newer than this NetGuard ({SCHEMA_VERSION}); upgrade NetGuard"
                )
            for version in range(current, SCHEMA_VERSION):
                for statement in MIGRATIONS[version].split(";"):
                    if statement.strip():
                        conn.execute(statement)
            conn.execute(
                "INSERT INTO meta (key, value) VALUES ('schema_version', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (str(SCHEMA_VERSION),),
            )
        return SCHEMA_VERSION

    # ------------------------------------------------------------- captures

    def add_capture(self, filename: str, sha256: str, size_bytes: int, fmt: str) -> tuple[dict[str, Any], bool]:
        """Insert a capture, or return the existing one with the same hash. Returns ``(row, created)``."""
        with self.transaction(immediate=True) as conn:
            row = conn.execute("SELECT * FROM captures WHERE sha256 = ?", (sha256,)).fetchone()
            if row is not None:
                return dict(row), False
            cid = new_id()
            conn.execute(
                "INSERT INTO captures (id, filename, sha256, size_bytes, format, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (cid, filename, sha256, size_bytes, fmt, time.time()),
            )
            return dict(conn.execute("SELECT * FROM captures WHERE id = ?", (cid,)).fetchone()), True

    def get_capture(self, capture_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM captures WHERE id = ?", (capture_id,)).fetchone()
            return dict(row) if row else None

    def list_captures(self, limit: int = 50, offset: int = 0, sort: str = "-created_at") -> Page:
        _page_bounds(limit, offset)
        order = _order(sort, _CAPTURE_SORTS)
        with self.connect() as conn:
            total = conn.execute("SELECT COUNT(*) FROM captures").fetchone()[0]
            rows = conn.execute(
                f"SELECT * FROM captures ORDER BY {order} LIMIT ? OFFSET ?",  # noqa: S608 - order from allowlist
                (limit, offset),
            ).fetchall()
        return Page([dict(r) for r in rows], total, limit, offset)

    def delete_capture(self, capture_id: str) -> bool:
        """Delete a capture and (by cascade) its analyses, alerts and flows. Refuses while a job runs."""
        with self.transaction(immediate=True) as conn:
            busy = conn.execute(
                "SELECT 1 FROM analyses WHERE capture_id = ? AND status IN ('queued', 'running')", (capture_id,)
            ).fetchone()
            if busy:
                raise StoreError("capture has queued or running analyses; cancel them first")
            return conn.execute("DELETE FROM captures WHERE id = ?", (capture_id,)).rowcount > 0

    # ------------------------------------------------------------- analyses

    def create_analysis(self, capture_id: str, config: dict[str, Any], version: str) -> dict[str, Any]:
        aid = new_id()
        with self.transaction() as conn:
            conn.execute(
                "INSERT INTO analyses (id, capture_id, status, config, created_at, netguard_version) "
                "VALUES (?, ?, 'queued', ?, ?, ?)",
                (aid, capture_id, json.dumps(config), time.time(), version),
            )
        analysis = self.get_analysis(aid)
        assert analysis is not None
        return analysis

    def get_analysis(self, analysis_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM analyses WHERE id = ?", (analysis_id,)).fetchone()
        return _analysis(row) if row else None

    def list_analyses(
        self,
        capture_id: str | None = None,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
        sort: str = "-created_at",
    ) -> Page:
        _page_bounds(limit, offset)
        order = _order(sort, _ANALYSIS_SORTS)
        where: list[str] = []
        params: list[object] = []
        if capture_id:
            where.append("capture_id = ?")
            params.append(capture_id)
        if status:
            if status not in STATUSES:
                raise StoreError(f"unknown status {status!r}")
            where.append("status = ?")
            params.append(status)
        clause = f"WHERE {' AND '.join(where)}" if where else ""
        with self.connect() as conn:
            total = conn.execute(f"SELECT COUNT(*) FROM analyses {clause}", params).fetchone()[0]  # noqa: S608
            rows = conn.execute(
                f"SELECT * FROM analyses {clause} ORDER BY {order} LIMIT ? OFFSET ?",  # noqa: S608
                [*params, limit, offset],
            ).fetchall()
        return Page([_analysis(r) for r in rows], total, limit, offset)

    def claim_next(self) -> dict[str, Any] | None:
        """Atomically move the oldest queued analysis to ``running`` and return it."""
        with self.transaction(immediate=True) as conn:
            row = conn.execute(
                "SELECT id FROM analyses WHERE status = 'queued' ORDER BY created_at, id LIMIT 1"
            ).fetchone()
            if row is None:
                return None
            conn.execute(
                "UPDATE analyses SET status = 'running', started_at = ?, attempts = attempts + 1, error = NULL "
                "WHERE id = ?",
                (time.time(), row["id"]),
            )
        return self.get_analysis(row["id"])

    def finish_analysis(self, analysis_id: str, status: str, error: str | None = None) -> bool:
        """Set a final status, only if the analysis is still running. Clears partial results on failure."""
        if status not in FINAL_STATUSES:
            raise ValueError(status)
        with self.transaction(immediate=True) as conn:
            changed = conn.execute(
                "UPDATE analyses SET status = ?, finished_at = ?, error = ? WHERE id = ? AND status = 'running'",
                (status, time.time(), error, analysis_id),
            ).rowcount
            if changed and status != "done":
                _clear_results(conn, analysis_id)
            return changed > 0

    def cancel_analysis(self, analysis_id: str) -> bool:
        """Cancel a queued or running analysis. The runner kills a running worker."""
        with self.transaction(immediate=True) as conn:
            changed = conn.execute(
                "UPDATE analyses SET status = 'cancelled', finished_at = ?, error = 'cancelled by user' "
                "WHERE id = ? AND status IN ('queued', 'running')",
                (time.time(), analysis_id),
            ).rowcount
            if changed:
                _clear_results(conn, analysis_id)
            return changed > 0

    def status(self, analysis_id: str) -> str | None:
        with self.connect() as conn:
            row = conn.execute("SELECT status FROM analyses WHERE id = ?", (analysis_id,)).fetchone()
        return row["status"] if row else None

    def recover_interrupted(self, max_attempts: int = 2) -> tuple[int, int]:
        """After a restart: re-queue analyses left ``running``, or fail them after ``max_attempts``."""
        with self.transaction(immediate=True) as conn:
            stuck = conn.execute("SELECT id, attempts FROM analyses WHERE status = 'running'").fetchall()
            requeued = failed = 0
            for row in stuck:
                _clear_results(conn, row["id"])
                if row["attempts"] < max_attempts:
                    conn.execute("UPDATE analyses SET status = 'queued', started_at = NULL WHERE id = ?", (row["id"],))
                    requeued += 1
                else:
                    conn.execute(
                        "UPDATE analyses SET status = 'failed', finished_at = ?, "
                        "error = 'interrupted (worker or server stopped) too many times' WHERE id = ?",
                        (time.time(), row["id"]),
                    )
                    failed += 1
        return requeued, failed

    # -------------------------------------------------------- worker writes

    def insert_flows(self, analysis_id: str, flows: Sequence[Flow]) -> None:
        rows = [
            (
                analysis_id,
                f.proto,
                f.src_ip,
                f.src_port,
                f.dst_ip,
                f.dst_port,
                f.first_seen,
                f.last_seen,
                f.duration,
                f.state,
                f.history,
                f.orig_packets,
                f.orig_bytes,
                f.orig_payload_bytes,
                f.resp_packets,
                f.resp_bytes,
                f.resp_payload_bytes,
                f.retransmissions,
                f.seq_gaps,
                f.end_reason,
            )
            for f in flows
        ]
        columns = ", ".join(("analysis_id", *_FLOW_COLUMNS))
        marks = ", ".join("?" * (len(_FLOW_COLUMNS) + 1))
        with self.transaction() as conn:
            conn.executemany(f"INSERT INTO flows ({columns}) VALUES ({marks})", rows)  # noqa: S608 - constants

    def complete_analysis(
        self,
        analysis_id: str,
        alerts: Iterable[Alert],
        stats: dict[str, Any],
        capture_info: dict[str, Any],
        flow_count: int,
        flows_truncated: int,
    ) -> bool:
        """Store the alerts and summary and mark the analysis done, unless it was cancelled meanwhile."""
        with self.transaction(immediate=True) as conn:
            row = conn.execute("SELECT status FROM analyses WHERE id = ?", (analysis_id,)).fetchone()
            if row is None or row["status"] != "running":
                return False
            count = 0
            for a in alerts:
                doc = a.to_dict()
                conn.execute(
                    "INSERT INTO alerts (analysis_id, alert_id, rule_id, detector, severity, title, src, dst, "
                    "first_seen, last_seen, technique, summary, doc) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        analysis_id,
                        a.alert_id,
                        a.rule_id,
                        a.detector,
                        int(a.severity),
                        a.title,
                        a.src,
                        a.dst,
                        a.first_seen,
                        a.last_seen,
                        a.technique.id if a.technique else None,
                        a.summary,
                        json.dumps(doc),
                    ),
                )
                count += 1
            conn.execute(
                "UPDATE analyses SET status = 'done', finished_at = ?, stats = ?, capture_info = ?, "
                "alert_count = ?, flow_count = ?, flows_truncated = ? WHERE id = ?",
                (
                    time.time(),
                    json.dumps(stats),
                    json.dumps(capture_info),
                    count,
                    flow_count,
                    flows_truncated,
                    analysis_id,
                ),
            )
        return True

    # --------------------------------------------------------------- search

    def search_alerts(
        self,
        analysis_id: str | None = None,
        rule_id: str | None = None,
        severity: str | None = None,
        min_severity: str | None = None,
        ip: str | None = None,
        q: str | None = None,
        since: float | None = None,
        until: float | None = None,
        limit: int = 50,
        offset: int = 0,
        sort: str = "-first_seen",
    ) -> Page:
        _page_bounds(limit, offset)
        order = _order(sort, _ALERT_SORTS)
        where: list[str] = []
        params: list[object] = []
        if analysis_id:
            where.append("analysis_id = ?")
            params.append(analysis_id)
        if rule_id:
            where.append("rule_id = ?")
            params.append(rule_id)
        for value, op in ((severity, "="), (min_severity, ">=")):
            if value:
                if value.upper() not in SEVERITIES:
                    raise StoreError(f"unknown severity {value!r}")
                where.append(f"severity {op} ?")
                params.append(SEVERITIES[value.upper()])
        if ip:
            where.append("(src = ? OR dst = ?)")
            params += [ip, ip]
        if q:
            where.append("(summary LIKE ? ESCAPE '\\' OR title LIKE ? ESCAPE '\\')")
            params += [_like(q), _like(q)]
        if since is not None:
            where.append("last_seen >= ?")
            params.append(since)
        if until is not None:
            where.append("first_seen <= ?")
            params.append(until)
        clause = f"WHERE {' AND '.join(where)}" if where else ""
        with self.connect() as conn:
            total = conn.execute(f"SELECT COUNT(*) FROM alerts {clause}", params).fetchone()[0]  # noqa: S608
            rows = conn.execute(
                f"SELECT id, analysis_id, doc FROM alerts {clause} ORDER BY {order} LIMIT ? OFFSET ?",  # noqa: S608
                [*params, limit, offset],
            ).fetchall()
        return Page([_alert(r) for r in rows], total, limit, offset)

    def get_alert(self, alert_row_id: int) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute("SELECT id, analysis_id, doc FROM alerts WHERE id = ?", (alert_row_id,)).fetchone()
        return _alert(row) if row else None

    def iter_alerts(self, analysis_id: str) -> Iterator[dict[str, Any]]:
        """All alerts of one analysis in time order (for exports)."""
        with self.connect() as conn:
            for row in conn.execute(
                "SELECT id, analysis_id, doc FROM alerts WHERE analysis_id = ? ORDER BY first_seen, id",
                (analysis_id,),
            ):
                yield _alert(row)

    def search_flows(
        self,
        analysis_id: str,
        proto: str | None = None,
        state: str | None = None,
        ip: str | None = None,
        port: int | None = None,
        limit: int = 50,
        offset: int = 0,
        sort: str = "first_seen",
    ) -> Page:
        _page_bounds(limit, offset)
        order = _order(sort, _FLOW_SORTS)
        where: list[str] = ["analysis_id = ?"]
        params: list[object] = [analysis_id]
        for column, value in (("proto", proto), ("state", state)):
            if value:
                where.append(f"{column} = ?")
                params.append(value)
        if ip:
            where.append("(src_ip = ? OR dst_ip = ?)")
            params += [ip, ip]
        if port is not None:
            where.append("(src_port = ? OR dst_port = ?)")
            params += [port, port]
        clause = " AND ".join(where)
        with self.connect() as conn:
            total = conn.execute(f"SELECT COUNT(*) FROM flows WHERE {clause}", params).fetchone()[0]  # noqa: S608
            rows = conn.execute(
                f"SELECT * FROM flows WHERE {clause} ORDER BY {order} LIMIT ? OFFSET ?",  # noqa: S608
                [*params, limit, offset],
            ).fetchall()
        return Page([_flow(r) for r in rows], total, limit, offset)


def _clear_results(conn: sqlite3.Connection, analysis_id: str) -> None:
    conn.execute("DELETE FROM alerts WHERE analysis_id = ?", (analysis_id,))
    conn.execute("DELETE FROM flows WHERE analysis_id = ?", (analysis_id,))


def _analysis(row: sqlite3.Row) -> dict[str, Any]:
    out = dict(row)
    for key in ("config", "stats", "capture_info"):
        out[key] = json.loads(out[key]) if out[key] else None
    out["flows_truncated"] = bool(out["flows_truncated"])
    return out


def _alert(row: sqlite3.Row) -> dict[str, Any]:
    doc: dict[str, Any] = json.loads(row["doc"])
    return {"id": row["id"], "analysis_id": row["analysis_id"], **doc}


def _flow(row: sqlite3.Row) -> dict[str, Any]:
    """Same shape as ``Flow.to_dict()`` plus the row id."""
    out = dict(row)
    out.pop("analysis_id", None)
    out["first_seen"] = iso_ts(out["first_seen"])
    out["last_seen"] = iso_ts(out["last_seen"])
    out["duration_seconds"] = round(out.pop("duration"), 6)
    return out
