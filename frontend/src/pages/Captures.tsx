import { useRef, useState } from "react";
import { Link, useNavigate } from "react-router";
import { type Capture, api, uploadCapture } from "../api";
import { Empty, ErrorBox, Loading, Pagination, Panel, StatusBadge } from "../components/ui";
import { formatBytes, formatTime, timeAgo } from "../format";
import { useAsync } from "../hooks";

const LIMIT = 20;
const ACCEPT = ".pcap,.pcapng,.cap,application/vnd.tcpdump.pcap,application/octet-stream";

function Upload({ onUploaded }: { onUploaded: (c: Capture) => void }) {
  const input = useRef<HTMLInputElement>(null);
  const [progress, setProgress] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);

  async function send(file: File) {
    setError(null);
    setProgress(0);
    try {
      const capture = await uploadCapture(file, setProgress);
      onUploaded(capture);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setProgress(null);
      if (input.current) input.current.value = "";
    }
  }

  return (
    <div
      className={`dropzone${dragging ? " dragging" : ""}`}
      onDragOver={(e) => {
        e.preventDefault();
        setDragging(true);
      }}
      onDragLeave={() => setDragging(false)}
      onDrop={(e) => {
        e.preventDefault();
        setDragging(false);
        const file = e.dataTransfer.files[0];
        if (file) void send(file);
      }}
    >
      <p>
        <strong>Drop a pcap or pcapng file here</strong> or{" "}
        <button type="button" className="btn btn-primary" onClick={() => input.current?.click()} disabled={progress !== null}>
          Choose file
        </button>
      </p>
      <input
        ref={input}
        type="file"
        accept={ACCEPT}
        className="sr-only"
        aria-label="Capture file"
        onChange={(e) => {
          const file = e.target.files?.[0];
          if (file) void send(file);
        }}
      />
      {progress !== null ? (
        <div className="progress" role="progressbar" aria-valuenow={Math.round(progress * 100)} aria-valuemin={0} aria-valuemax={100}>
          <div className="progress-fill" style={{ width: `${progress * 100}%` }} />
          <span>{progress < 1 ? `Uploading ${Math.round(progress * 100)}%` : "Verifying…"}</span>
        </div>
      ) : null}
      {error ? (
        <div className="state error" role="alert">
          Upload failed: {error}
        </div>
      ) : (
        <p className="muted small">The file is checked to be a capture, hashed, and stored on the server only.</p>
      )}
    </div>
  );
}

function CaptureRow({
  capture,
  profileId,
  onDeleted,
}: {
  capture: Capture;
  profileId: string | null;
  onDeleted: () => void;
}) {
  const navigate = useNavigate();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const analyses = useAsync(() => api.analyses({ capture_id: capture.id, limit: 5 }), [capture.id]);

  async function run(action: () => Promise<void>) {
    setBusy(true);
    setError(null);
    try {
      await action();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <tr>
      <td className="wrap">
        <strong>{capture.filename}</strong>
        <div className="muted mono small" title={capture.sha256}>
          {capture.format} · sha256 {capture.sha256.slice(0, 12)}…
        </div>
        {error ? (
          <div className="sev-text-high small" role="alert">
            {error}
          </div>
        ) : null}
      </td>
      <td className="num nowrap">{formatBytes(capture.size_bytes)}</td>
      <td className="nowrap" title={formatTime(capture.created_at)}>
        {timeAgo(capture.created_at)}
      </td>
      <td>
        {analyses.data?.items.length ? (
          <ul className="list compact">
            {analyses.data.items.map((a) => (
              <li key={a.id}>
                <Link to={`/analyses/${a.id}`} className="mono">
                  {a.id.slice(0, 8)}
                </Link>
                <StatusBadge status={a.status} />
                {a.status === "done" ? <span className="muted">{a.alert_count} alerts</span> : null}
              </li>
            ))}
          </ul>
        ) : (
          <span className="muted">{analyses.loading ? "…" : "none yet"}</span>
        )}
      </td>
      <td className="actions">
        <button
          type="button"
          className="btn btn-primary"
          disabled={busy}
          onClick={() =>
            void run(async () => {
              const analysis = await api.analyse(capture.id, profileId);
              navigate(`/analyses/${analysis.id}`);
            })
          }
        >
          Analyse
        </button>
        <button
          type="button"
          className="btn btn-danger"
          disabled={busy}
          onClick={() => {
            if (window.confirm(`Delete ${capture.filename} and all its analyses?`)) {
              void run(async () => {
                await api.deleteCapture(capture.id);
                onDeleted();
              });
            }
          }}
        >
          Delete
        </button>
      </td>
    </tr>
  );
}

export function Captures() {
  const [offset, setOffset] = useState(0);
  const [profileId, setProfileId] = useState<string | null>(null);
  const captures = useAsync(() => api.captures({ limit: LIMIT, offset }), [offset]);
  const profiles = useAsync(() => api.profiles(), []);

  return (
    <>
      <h1>Captures</h1>
      <Panel title="Upload">
        <Upload
          onUploaded={() => {
            setOffset(0);
            captures.reload();
          }}
        />
      </Panel>
      <Panel
        title="Stored captures"
        actions={
          <label className="inline">
            Rule profile{" "}
            <select value={profileId ?? ""} onChange={(e) => setProfileId(e.target.value || null)}>
              <option value="">Server defaults</option>
              {profiles.data?.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </select>
          </label>
        }
      >
        {captures.error ? <ErrorBox error={captures.error} retry={captures.reload} /> : null}
        {captures.loading && !captures.data ? <Loading /> : null}
        {captures.data && captures.data.total === 0 ? (
          <Empty title="No captures stored">Upload one above, or generate lab captures with `netguard lab generate`.</Empty>
        ) : null}
        {captures.data && captures.data.total > 0 ? (
          <>
            <div className="table-wrap">
              <table className="data">
                <thead>
                  <tr>
                    <th>Capture</th>
                    <th className="num">Size</th>
                    <th>Uploaded</th>
                    <th>Recent analyses</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {captures.data.items.map((c) => (
                    <CaptureRow key={c.id} capture={c} profileId={profileId} onDeleted={captures.reload} />
                  ))}
                </tbody>
              </table>
            </div>
            <Pagination total={captures.data.total} limit={LIMIT} offset={offset} onChange={setOffset} />
          </>
        ) : null}
      </Panel>
      {profiles.data && profiles.data.length === 0 ? (
        <p className="muted small">
          Tip: create rule profiles under <Link to="/rules">Rules</Link> to analyse with different thresholds.
        </p>
      ) : null}
    </>
  );
}
