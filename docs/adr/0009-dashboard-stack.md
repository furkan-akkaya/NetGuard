# ADR-0009: Dashboard — React + TypeScript SPA served by the API

- **Status:** Accepted
- **Date:** 2026-10-22

## Context

Phase 5 needs a responsive analysis dashboard on top of the v1 API: overview,
traffic statistics, flows and endpoints, an alert feed with evidence, capture
upload and job progress, rule management, reports and exports, with real
loading, empty and error states. Every string it shows (DNS names, evidence)
can come from a hostile capture.

## Options

| Option | For | Against |
|---|---|---|
| Server-rendered Jinja2 + htmx | No build step, Python only | Interactive tables, polling, charts and filters become many partial templates; less transferable as a portfolio skill |
| **React + TypeScript + Vite SPA** | Typed client for a typed API; components testable with Vitest; the industry-standard stack for security consoles; React escapes text by default | A Node toolchain for development and release builds |
| Vanilla JS modules | No dependencies | Becomes an ad-hoc framework at this size; no type checking |

## Decision

React 19 + TypeScript (strict) + Vite, in `frontend/`. The production build is
written to `src/netguard/web/static/` (git-ignored) and served by FastAPI at
`/`, so there is one process, one origin and no CORS. Runtime dependencies are
limited to `react`, `react-dom` and `react-router`; charts are small SVG
components written for this project instead of a charting library (four chart
types are needed, each under 100 lines, and every chart has a table or text
equivalent).

Security:

- No `dangerouslySetInnerHTML`, no `eval`, no inline scripts: a strict
  Content-Security-Policy (`script-src 'self'`, `frame-ancestors 'none'`, …) is
  sent with the dashboard, and a Vitest test renders hostile capture strings.
- The API token, when the server requires one, is kept in `sessionStorage`
  (gone when the tab closes) and sent as a bearer header; cookies are not used,
  so there is no CSRF surface.
- Same origin only; the API sends no CORS headers.

If the bundle is missing (e.g. a Python-only install from source), `/` explains
how to build it; the API keeps working.

## Consequences

- Development needs Node and pnpm; CI gains a frontend job (type check, tests,
  build). Release wheels must be built after the frontend (Phase 9/10).
- Charts are deliberately simple (bars, time series); anything richer would
  justify a library and a new ADR.
