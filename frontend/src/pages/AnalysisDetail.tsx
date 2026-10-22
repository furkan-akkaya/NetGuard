import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router";
import { type Analysis, type Stats, api, download } from "../api";
import { AlertTable } from "../components/AlertTable";
import { BarList, TimeSeries } from "../components/charts";
import { FlowBrowser } from "../components/FlowBrowser";
import { Empty, ErrorBox, Loading, Panel, Stat, StatusBadge } from "../components/ui";
import { endpoint, formatBytes, formatDuration, formatNumber, formatTime } from "../format";
import { useAsync } from "../hooks";

const active = (a: Analysis | undefined) => !!a && (a.status === "queued" || a.status === "running");

function Traffic({ stats }: { stats: Stats }) {
  const [unit, setUnit] = useState<"packets" | "bytes">("packets");
  const points = stats.timeseries.buckets.map((b) => ({ t: b.start, value: unit === "bytes" ? b.bytes : b.packets }));
  return (
    <>
      <div className="stats">
        <Stat label="Packets" value={formatNumber(stats.packets)} hint={`${formatNumber(stats.decode_errors)} decode errors`} />
        <Stat label="Bytes" value={formatBytes(stats.bytes)} />
        <Stat label="Duration" value={formatDuration(stats.duration_seconds)} hint={formatTime(stats.first_seen)} />
        <Stat
          label="Flows"
          value={formatNumber(stats.flows.total)}
          hint={stats.flows.evicted ? `${formatNumber(stats.flows.evicted)} evicted early` : undefined}
        />
        <Stat label="Retransmissions" value={formatNumber(stats.flows.retransmissions)} />
        <Stat label="Fragments" value={formatNumber(stats.fragments)} />
      </div>
      <Panel
        title="Traffic over time"
        actions={
          <div className="segmented" role="group" aria-label="Unit">
            {(["packets", "bytes"] as const).map((u) => (
              <button key={u} type="button" className={unit === u ? "on" : ""} aria-pressed={unit === u} onClick={() => setUnit(u)}>
                {u}
              </button>
            ))}
          </div>
        }
      >
        <TimeSeries points={points} bucketSeconds={stats.timeseries.bucket_seconds} unit={unit} />
      </Panel>
      <div className="grid-3">
        <Panel title="Protocols">
          <BarList items={Object.entries(stats.protocols).map(([label, value]) => ({ label, value }))} valueLabel="Packets" />
        </Panel>
        <Panel title="Connection states">
          <BarList items={Object.entries(stats.flows.states).map(([label, value]) => ({ label, value }))} valueLabel="Flows" />
        </Panel>
        <Panel title="Top services">
          <BarList items={stats.flows.top_services.map((s) => ({ label: s.service, value: s.flows }))} valueLabel="Flows" />
        </Panel>
      </div>
      <div className="grid-2">
        <Panel title={`Top endpoints${stats.endpoints.approximate ? " (approximate)" : ""}`}>
          <div className="table-wrap">
            <table className="data">
              <thead>
                <tr>
                  <th>IP</th>
                  <th className="num">Sent</th>
                  <th className="num">Received</th>
                  <th className="num">Flows out</th>
                  <th className="num">Flows in</th>
                </tr>
              </thead>
              <tbody>
                {stats.endpoints.top_by_bytes.map((e) => (
                  <tr key={e.ip}>
                    <td className="mono">{e.ip}</td>
                    <td className="num">{formatBytes(e.bytes_sent)}</td>
                    <td className="num">{formatBytes(e.bytes_received)}</td>
                    <td className="num">{formatNumber(e.flows_originated)}</td>
                    <td className="num">{formatNumber(e.flows_responded)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
        <Panel title="Packet sizes">
          <BarList
            items={Object.entries(stats.packet_sizes).map(([label, value]) => ({ label: `${label} B`, value }))}
            valueLabel="Packets"
          />
        </Panel>
      </div>
      <Panel title="Largest flows">
        <div className="table-wrap">
          <table className="data">
            <thead>
              <tr>
                <th>Flow</th>
                <th>State</th>
                <th className="num">Bytes</th>
                <th className="num">Packets</th>
                <th className="num">Duration</th>
              </tr>
            </thead>
            <tbody>
              {stats.flows.top_by_bytes.map((f, i) => (
                <tr key={i}>
                  <td className="mono">
                    {f.proto} {endpoint(f.src_ip, f.src_port)} → {endpoint(f.dst_ip, f.dst_port)}
                  </td>
                  <td className="mono">{f.state}</td>
                  <td className="num">{formatBytes(f.orig_bytes + f.resp_bytes)}</td>
                  <td className="num">{formatNumber(f.orig_packets + f.resp_packets)}</td>
                  <td className="num">{formatDuration(f.duration_seconds)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>
    </>
  );
}

function Exports({ analysis }: { analysis: Analysis }) {
  const [error, setError] = useState<string | null>(null);
  const id = analysis.id;
  const get = (path: string, name: string) => {
    setError(null);
    download(path, name).catch((e: unknown) => setError(e instanceof Error ? e.message : String(e)));
  };
  return (
    <div className="button-row">
      <button type="button" className="btn" onClick={() => get(`/analyses/${id}/report.html`, `netguard-report-${id}.html`)}>
        HTML report
      </button>
      <button type="button" className="btn" onClick={() => get(`/analyses/${id}/alerts.ndjson`, `netguard-alerts-${id}.ndjson`)}>
        Alerts (NDJSON)
      </button>
      <button
        type="button"
        className="btn"
        onClick={() => get(`/analyses/${id}/alerts.ndjson?format=ecs`, `netguard-alerts-${id}-ecs.ndjson`)}
      >
        Alerts (ECS)
      </button>
      <button type="button" className="btn" onClick={() => get(`/analyses/${id}/flows.csv`, `netguard-flows-${id}.csv`)}>
        Flows (CSV)
      </button>
      {error ? (
        <span className="sev-text-high" role="alert">
          {error}
        </span>
      ) : null}
    </div>
  );
}

function Reanalyse({ analysis }: { analysis: Analysis }) {
  const navigate = useNavigate();
  const profiles = useAsync(() => api.profiles(), []);
  const [profileId, setProfileId] = useState("");
  const [error, setError] = useState<string | null>(null);
  return (
    <div className="button-row">
      <label className="inline">
        Profile{" "}
        <select value={profileId} onChange={(e) => setProfileId(e.target.value)}>
          <option value="">Server defaults</option>
          {profiles.data?.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name}
            </option>
          ))}
        </select>
      </label>
      <button
        type="button"
        className="btn"
        onClick={() => {
          setError(null);
          api
            .analyse(analysis.capture_id, profileId || null)
            .then((a) => navigate(`/analyses/${a.id}`))
            .catch((e: unknown) => setError(e instanceof Error ? e.message : String(e)));
        }}
      >
        Re-analyse
      </button>
      {error ? <span className="sev-text-high">{error}</span> : null}
    </div>
  );
}

export function AnalysisDetail() {
  const { id = "" } = useParams();
  const { data: analysis, error, loading, reload } = useAsync(() => api.analysis(id), [id], {
    everyMs: 1000,
    while: active,
  });
  const capture = useAsync(
    () => (analysis ? api.capture(analysis.capture_id) : Promise.resolve(undefined)),
    [analysis?.capture_id],
  );
  const done = analysis?.status === "done";
  const alerts = useAsync(
    () => (done ? api.alerts({ analysis_id: id, limit: 100, sort: "-severity" }) : Promise.resolve(undefined)),
    [id, done],
  );

  if (error) return <ErrorBox error={error} retry={reload} />;
  if (loading && !analysis) return <Loading />;
  if (!analysis) return null;

  return (
    <>
      <div className="title-row">
        <h1>
          Analysis <span className="mono">{analysis.id.slice(0, 8)}</span>
        </h1>
        <StatusBadge status={analysis.status} />
      </div>
      <p className="muted">
        Capture <strong>{capture.data?.filename ?? analysis.capture_id.slice(0, 8)}</strong> · queued {formatTime(analysis.created_at)}
        {analysis.finished_at ? ` · finished ${formatTime(analysis.finished_at)}` : ""} · NetGuard {analysis.netguard_version}
        {analysis.profile_id ? " · with a rule profile" : ""}
      </p>

      {active(analysis) ? (
        <div className="state">
          <span className="spinner" aria-hidden="true" />
          {analysis.status === "queued" ? "Waiting for a worker…" : "Analysing the capture…"}
          <button type="button" className="btn btn-danger" onClick={() => void api.cancel(analysis.id).then(reload)}>
            Cancel
          </button>
        </div>
      ) : null}
      {analysis.status === "failed" ? (
        <div className="state error" role="alert">
          <strong>The analysis failed</strong>
          <div>{analysis.error}</div>
        </div>
      ) : null}
      {analysis.status === "cancelled" ? <Empty title="This analysis was cancelled" /> : null}

      {done && analysis.stats ? (
        <>
          <Panel title="Actions">
            <Exports analysis={analysis} />
            <Reanalyse analysis={analysis} />
            {analysis.capture_info?.truncated ? (
              <p className="sev-text-medium">The capture ends with a truncated record; the complete part was analysed.</p>
            ) : null}
            {analysis.flows_truncated ? (
              <p className="sev-text-medium">
                Only the first {formatNumber(analysis.flow_count)} flows were stored (server limit); statistics cover all of them.
              </p>
            ) : null}
          </Panel>
          <Panel title={`Alerts (${analysis.alert_count})`}>
            {alerts.error ? <ErrorBox error={alerts.error} retry={alerts.reload} /> : null}
            {alerts.data ? (
              alerts.data.total === 0 ? (
                <p className="muted">No rule fired on this capture.</p>
              ) : (
                <>
                  <AlertTable alerts={alerts.data.items} />
                  {alerts.data.total > alerts.data.items.length ? (
                    <Link to={`/alerts?analysis_id=${analysis.id}`}>All {alerts.data.total} alerts</Link>
                  ) : null}
                </>
              )
            ) : (
              <Loading />
            )}
          </Panel>
          <Traffic stats={analysis.stats} />
          <Panel title={`Flows (${formatNumber(analysis.flow_count)} stored)`}>
            <FlowBrowser analysisId={analysis.id} />
          </Panel>
        </>
      ) : null}
    </>
  );
}
