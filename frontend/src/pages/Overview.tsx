import { Link } from "react-router";
import { api } from "../api";
import { AlertTable } from "../components/AlertTable";
import { BarList } from "../components/charts";
import { Empty, ErrorBox, Loading, Panel, Stat, StatusBadge } from "../components/ui";
import { formatBytes, formatNumber, timeAgo } from "../format";
import { useAsync } from "../hooks";

export function Overview() {
  const { data, error, loading, reload } = useAsync(() => api.summary(), [], {
    everyMs: 3000,
    while: (s) => !!s && (s.analyses.queued > 0 || s.analyses.running > 0),
  });
  if (error) return <ErrorBox error={error} retry={reload} />;
  if (loading && !data) return <Loading />;
  if (!data) return null;
  const totalAlerts = data.alerts.HIGH + data.alerts.MEDIUM + data.alerts.LOW;
  const finished = data.analyses.done + data.analyses.failed + data.analyses.cancelled;

  return (
    <>
      <h1>Security overview</h1>
      {data.captures === 0 ? (
        <Empty title="No captures yet">
          <Link to="/captures">Upload a pcap or pcapng file</Link> to analyse it.
        </Empty>
      ) : null}
      <div className="stats">
        <Stat label="Alerts" value={formatNumber(totalAlerts)} hint="across all stored analyses" />
        <Stat label="High" value={<span className="sev-text-high">{formatNumber(data.alerts.HIGH)}</span>} />
        <Stat label="Medium" value={<span className="sev-text-medium">{formatNumber(data.alerts.MEDIUM)}</span>} />
        <Stat label="Low" value={<span className="sev-text-low">{formatNumber(data.alerts.LOW)}</span>} />
        <Stat label="Captures" value={formatNumber(data.captures)} hint={formatBytes(data.capture_bytes)} />
        <Stat
          label="Analyses"
          value={formatNumber(finished)}
          hint={
            data.analyses.running + data.analyses.queued
              ? `${data.analyses.running + data.analyses.queued} in progress`
              : `${data.analyses.failed} failed`
          }
        />
      </div>
      <div className="grid-2">
        <Panel title="Alerts by rule">
          <BarList items={data.alerts_by_rule.map((r) => ({ label: r.rule_id, value: r.count }))} valueLabel="Alerts" />
        </Panel>
        <Panel title="Recent analyses" actions={<Link to="/captures">All captures</Link>}>
          {data.recent_analyses.length === 0 ? (
            <p className="muted">No analyses yet.</p>
          ) : (
            <ul className="list">
              {data.recent_analyses.map((a) => (
                <li key={a.id}>
                  <Link to={`/analyses/${a.id}`} className="mono">
                    {a.id.slice(0, 8)}
                  </Link>
                  <StatusBadge status={a.status} />
                  <span className="muted">
                    {a.status === "done" ? `${a.alert_count} alerts · ${formatNumber(a.flow_count)} flows · ` : ""}
                    {timeAgo(a.created_at)}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>
      <Panel title="Most severe recent alerts" actions={<Link to="/alerts">All alerts</Link>}>
        {data.recent_alerts.length ? (
          <AlertTable alerts={data.recent_alerts} showAnalysis />
        ) : (
          <p className="muted">No alerts.</p>
        )}
      </Panel>
    </>
  );
}
