import type { ReactNode } from "react";
import { ApiError, type Severity, type Status } from "../api";

export function Loading({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="state" role="status" aria-live="polite">
      <span className="spinner" aria-hidden="true" />
      {label}
    </div>
  );
}

export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="state empty">
      <strong>{title}</strong>
      {children ? <div className="muted">{children}</div> : null}
    </div>
  );
}

export function ErrorBox({ error, retry }: { error: Error; retry?: () => void }) {
  const auth = error instanceof ApiError && error.status === 401;
  return (
    <div className="state error" role="alert">
      <strong>{auth ? "Authentication required" : "Something went wrong"}</strong>
      <div>{auth ? "This server requires an API token. Set it under Settings." : error.message}</div>
      {retry && !auth ? (
        <button type="button" className="btn" onClick={retry}>
          Retry
        </button>
      ) : null}
    </div>
  );
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`badge sev-${severity.toLowerCase()}`}>{severity}</span>;
}

export function StatusBadge({ status }: { status: Status }) {
  return (
    <span className={`badge status-${status}`}>
      {status === "running" || status === "queued" ? <span className="dot" aria-hidden="true" /> : null}
      {status}
    </span>
  );
}

export function Stat({ label, value, hint }: { label: string; value: ReactNode; hint?: ReactNode }) {
  return (
    <div className="stat">
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
      {hint ? <div className="stat-hint">{hint}</div> : null}
    </div>
  );
}

export function Panel({ title, actions, children }: { title: string; actions?: ReactNode; children: ReactNode }) {
  return (
    <section className="panel">
      <header className="panel-head">
        <h2>{title}</h2>
        {actions ? <div className="panel-actions">{actions}</div> : null}
      </header>
      {children}
    </section>
  );
}

export function Pagination({
  total,
  limit,
  offset,
  onChange,
}: {
  total: number;
  limit: number;
  offset: number;
  onChange: (offset: number) => void;
}) {
  if (total <= limit) return total ? <div className="pager muted">{total} total</div> : null;
  const page = Math.floor(offset / limit) + 1;
  const pages = Math.ceil(total / limit);
  return (
    <nav className="pager" aria-label="Pagination">
      <button type="button" className="btn" disabled={offset === 0} onClick={() => onChange(offset - limit)}>
        Previous
      </button>
      <span className="muted">
        Page {page} of {pages} · {total.toLocaleString("en-US")} total
      </span>
      <button type="button" className="btn" disabled={page >= pages} onClick={() => onChange(offset + limit)}>
        Next
      </button>
    </nav>
  );
}
