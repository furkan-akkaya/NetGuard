# REST API (v1)

`netguard serve` runs a REST API for uploading captures, running analyses and
searching the results, and serves the web dashboard at `/` (ADR-0009). Design and security decisions: [ADR-0008](adr/0008-backend-storage-and-api.md).
The live, generated reference (OpenAPI) is served at `/api/v1/docs` and
`/api/v1/openapi.json`.

```bash
pip install 'netguard[web]'          # or: uv sync --all-extras
netguard serve --data-dir ./netguard-data                      # http://127.0.0.1:8000
NETGUARD_API_TOKEN=$(python -c "import secrets; print(secrets.token_urlsafe(32))") \
  netguard serve --host 0.0.0.0 --data-dir /var/lib/netguard   # remote access needs a token (and TLS in front)
```

| Option | Default | Meaning |
|---|---|---|
| `--data-dir` | `netguard-data` | SQLite database and stored captures (created `0700`) |
| `--host`, `--port` | `127.0.0.1`, `8000` | Bind address; non-loopback requires `NETGUARD_API_TOKEN` |
| `-c, --config` | built-in defaults | Base TOML configuration for every analysis |
| `--max-upload-mb` | 256 | Upload cap, enforced while streaming |
| `--job-timeout` | 600 | Seconds per analysis before the worker is killed |
| `--job-memory-mb` | 1024 | Worker address-space limit (enforced on Linux) |
| `--max-stored-flows` | 500 000 | Flow rows kept per analysis (`flows_truncated` reports the rest) |

## Conventions

- Base path `/api/v1`. JSON everywhere except uploads (raw body) and exports (NDJSON).
- Authentication: `Authorization: Bearer <token>` on every route except
  `/health`, when the server has a token.
- Timestamps are ISO 8601 UTC strings; `since`/`until` filters take Unix time.
- Lists return `{"items": [...], "total": N, "limit": L, "offset": O}`;
  `limit` is 1–1000 (default 50); `sort` is a field name, `-` for descending.
- Errors: `{"detail": "..."}` with 400 (bad query), 401, 404, 409 (conflict),
  413 (too large), 415 (not a capture), 422 (validation).

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Liveness, version, schema version (no auth) |
| GET | `/summary` | Overview: counts by status and severity, alerts by rule, recent alerts and analyses |
| GET | `/rules` | All rules with state and settings in the base configuration |
| GET / POST | `/profiles` | Rule profiles: named configuration overrides (validated on save) |
| GET / PUT / DELETE | `/profiles/{id}` | One profile. Deleting it keeps the analyses that used it (their `profile_id` becomes null) |
| POST | `/captures?filename=…` | Upload a pcap/pcapng as the raw body. 201 created, 200 already stored (same SHA-256) |
| GET | `/captures` | List captures (`sort`: `created_at`, `size_bytes`, `filename`) |
| GET / DELETE | `/captures/{id}` | One capture / delete it with its analyses (409 while one is queued or running) |
| POST | `/captures/{id}/analyses` | Queue an analysis; body `{"profile_id": "...", "config": {...overrides...}}` (both optional; overrides apply on top of the profile). 202 |
| GET | `/analyses` | List (`capture_id`, `status`, `sort`: `created_at`, `finished_at`, `alert_count`) |
| GET | `/analyses/{id}` | Status, error, configuration snapshot, capture info and full statistics |
| POST | `/analyses/{id}/cancel` | Cancel a queued or running analysis (409 if finished) |
| GET | `/analyses/{id}/flows` | Flows: `proto`, `state`, `ip`, `port`; `sort`: `first_seen`, `duration`, `bytes`, `packets`, `src_ip`, `dst_ip`, `dst_port` |
| GET | `/analyses/{id}/alerts.ndjson?format=netguard\|ecs` | Export all alerts (native contract or Elastic Common Schema) |
| GET | `/analyses/{id}/flows.csv` | Export the stored flows as CSV |
| GET | `/analyses/{id}/report.html` | Single-file HTML report (no scripts; 409 until the analysis is done) |
| GET | `/alerts` | Search: `analysis_id`, `rule_id`, `severity`, `min_severity`, `ip` (src or dst), `q` (text), `since`, `until`; `sort`: `first_seen`, `last_seen`, `severity`, `rule_id`, `src`, `dst` |
| GET | `/alerts/{id}` | One alert with full evidence |

Analysis lifecycle: `queued → running → done | failed | cancelled`. A failed
analysis carries a short reason in `error` (invalid capture, timeout, out of
memory, crash). Jobs interrupted by a restart are re-queued once.

## Example session

```bash
B=http://127.0.0.1:8000/api/v1
CAP=$(curl -s -X POST "$B/captures?filename=scan.pcap" --data-binary @scan.pcap \
      -H 'Content-Type: application/octet-stream' | jq -r .id)
JOB=$(curl -s -X POST "$B/captures/$CAP/analyses" -H 'Content-Type: application/json' \
      -d '{"config": {"portscan": {"min_distinct_ports": 30}}}' | jq -r .id)
curl -s "$B/analyses/$JOB" | jq '{status, alert_count, flow_count, error}'
curl -s "$B/alerts?analysis_id=$JOB&min_severity=MEDIUM&sort=-severity" | jq '.items[] | {rule_id, severity, summary}'
curl -s "$B/analyses/$JOB/flows?state=S0&sort=-packets&limit=20" | jq '.items[] | [.src_ip, .dst_ip, .dst_port]'
curl -s "$B/analyses/$JOB/alerts.ndjson?format=ecs" > alerts-ecs.ndjson    # for Elastic / OpenSearch
```

## SIEM export (ECS)

`format=ecs` maps each alert onto ECS 8.x fields: `@timestamp`, `event.*`
(kind `alert`, category `network`/`intrusion_detection`, `id` = `alert_id`,
`severity` 21/47/73), `rule.*`, `source.ip`, `destination.ip` (or
`destination.domain` for DNS rules), `threat.technique.*`, `message`, and the
NetGuard evidence under `netguard.*`. The mapping lives in `netguard/events.py`.
