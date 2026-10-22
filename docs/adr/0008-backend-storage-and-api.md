# ADR-0008: Backend — SQLite storage, FastAPI, isolated analysis workers

- **Status:** Accepted
- **Date:** 2026-10-22

## Context

Phase 4 needs persistent captures, analysis jobs, flows and alerts, a job
lifecycle, and a versioned, documented, searchable API for the Phase 5
dashboard and for future SIEM integration. Constraints: one user or a small
team, a 4 GB Ubuntu server or a laptop, no cloud services, no microservices,
and the input files are hostile.

## Decisions

### Storage: SQLite (standard library), WAL mode

| Option | Verdict |
|---|---|
| **SQLite** | Zero administration, one file, transactional, in the standard library, millions of rows with indexes. WAL mode lets the API read while a worker writes. |
| PostgreSQL | Better concurrency and full-text search, but a server to install, secure and back up; no requirement here needs it. The schema stays portable SQL so a later move is possible. |
| DuckDB | Excellent for analytics over flows, but a native dependency and a single-writer model that fits batch, not a live API. Candidate for offline reporting later. |
| JSON files | No indexes, no filtering, no transactions. |

The schema is versioned in a `meta` table and migrated by ordered SQL scripts
(`store.py`). All SQL is parameterised; sort columns come from allowlists.

### API: FastAPI as an optional extra

FastAPI generates the OpenAPI document from typed models, validates input with
pydantic and serves both sync and async handlers. Flask would need extensions
for the same, and Litestar is comparable but less widely known (portfolio
readability matters). It ships as `pip install netguard[web]`: the analyzer
core keeps one runtime dependency (ADR-0001).

### Analysis in a separate, limited process

Parsing an uploaded pcap is the riskiest thing NetGuard does. Each analysis
job runs in its own `python -m netguard.worker` process:

- a crash, a parser bug or memory exhaustion kills one job, not the API;
- a wall-clock timeout kills the process group; on Linux `RLIMIT_AS` caps its
  memory and `RLIMIT_CPU` its CPU time (macOS does not enforce `RLIMIT_AS`;
  documented);
- one job runs at a time by default (`max_workers`), which keeps the 4 GB
  host predictable.

A runner thread in the API process claims queued jobs (`BEGIN IMMEDIATE`, so
two runners can never claim the same job), supervises the worker, and records
`done`, `failed` (with a short, sanitised reason) or `cancelled`. After a
crash or restart, jobs left `running` are re-queued once, then failed as
`interrupted`. Partial results of failed or cancelled jobs are deleted.

Rejected: running analysis in a thread of the API process (one bad pcap could
take the whole service down), Celery/RQ with Redis (a broker for one queue is
overengineering).

### Uploads: raw body, streamed, capped

`POST /api/v1/captures` takes the capture as the raw request body
(`application/octet-stream`, `curl --data-binary @x.pcap`), not multipart: the
body is streamed to disk while hashing, and the upload is aborted the moment
it exceeds `max_upload_bytes`, so an oversized upload never fills the disk.
The first bytes must be a pcap or pcapng magic number. Stored files are named
by a random id; the client's filename is metadata only and never touches the
filesystem. Identical uploads (same SHA-256) are de-duplicated.

### Secure defaults

The server binds to `127.0.0.1`. An API token (`NETGUARD_API_TOKEN`, sent as
`Authorization: Bearer …`, compared in constant time) protects every `/api`
route when set; binding to a non-loopback address without a token is refused
unless explicitly overridden. Pages are capped at 1000 items.

## Consequences

- Single-node by design. Multiple API processes would need a different job
  claim mechanism (or PostgreSQL).
- Flows can dominate storage (≈ 200 bytes per row); `max_stored_flows` caps
  rows per analysis and the cap is reported (`flows_truncated`).
- SQLite text search uses `LIKE`; full-text search can be added with FTS5 if
  needed.
