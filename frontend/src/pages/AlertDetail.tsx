import { Link, useParams } from "react-router";
import { api } from "../api";
import { FlowBrowser } from "../components/FlowBrowser";
import { ErrorBox, Loading, Panel, SeverityBadge } from "../components/ui";
import { formatDuration, formatTime, humanize } from "../format";
import { useAsync } from "../hooks";

const RULE_DOCS = "https://github.com/furkan-akkaya/NetGuard/blob/main/docs/rules/";

/** Render one evidence value. Strings come from the capture: always rendered as text. */
function Value({ value }: { value: unknown }) {
  if (value === null || value === undefined) return <span className="muted">–</span>;
  if (typeof value === "boolean") return <span>{value ? "yes" : "no"}</span>;
  if (typeof value === "number") return <span className="mono">{value.toLocaleString("en-US")}</span>;
  if (typeof value === "string") return <span className="mono break">{value}</span>;
  if (Array.isArray(value)) {
    if (value.length === 0) return <span className="muted">none</span>;
    if (value.every((v) => typeof v !== "object" || v === null)) {
      return (
        <ul className="chips">
          {value.map((v, i) => (
            <li key={i} className="mono">
              {String(v)}
            </li>
          ))}
        </ul>
      );
    }
    return <pre className="json">{JSON.stringify(value, null, 2)}</pre>;
  }
  return (
    <table className="kv nested">
      <tbody>
        {Object.entries(value as Record<string, unknown>).map(([k, v]) => (
          <tr key={k}>
            <th scope="row">{humanize(k)}</th>
            <td>
              <Value value={v} />
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export function AlertDetail() {
  const { id = "" } = useParams();
  const { data: alert, error, loading, reload } = useAsync(() => api.alert(id), [id]);
  if (error) return <ErrorBox error={error} retry={reload} />;
  if (loading && !alert) return <Loading />;
  if (!alert) return null;
  const seconds = (new Date(alert.last_seen).getTime() - new Date(alert.first_seen).getTime()) / 1000;
  const focusIp = alert.src ?? (alert.dst && /^[\d.:a-f]+$/i.test(alert.dst) ? alert.dst : "");

  return (
    <>
      <div className="title-row">
        <SeverityBadge severity={alert.severity} />
        <h1>{alert.title}</h1>
      </div>
      <p className="lead">{alert.summary}</p>
      <div className="grid-2">
        <Panel title="Details">
          <table className="kv">
            <tbody>
              <tr>
                <th scope="row">Source</th>
                <td className="mono">{alert.src ?? "–"}</td>
              </tr>
              <tr>
                <th scope="row">Target</th>
                <td className="mono break">{alert.dst ?? "–"}</td>
              </tr>
              <tr>
                <th scope="row">Observed</th>
                <td>
                  {formatTime(alert.first_seen)} → {formatTime(alert.last_seen)} ({formatDuration(seconds)})
                </td>
              </tr>
              {alert.reported_at ? (
                <tr>
                  <th scope="row">Reported</th>
                  <td>
                    {formatTime(alert.reported_at)} · detection delay{" "}
                    {formatDuration((new Date(alert.reported_at).getTime() - new Date(alert.first_seen).getTime()) / 1000)}
                    {alert.stage === "early" ? " · early warning (incident still open)" : ""}
                  </td>
                </tr>
              ) : null}
              <tr>
                <th scope="row">Rule</th>
                <td>
                  <a href={`${RULE_DOCS}${alert.rule_id}.md`} target="_blank" rel="noreferrer noopener" className="mono">
                    {alert.rule_id}
                  </a>{" "}
                  <span className="muted">({alert.detector})</span>
                </td>
              </tr>
              <tr>
                <th scope="row">MITRE ATT&amp;CK</th>
                <td>
                  {alert.technique ? (
                    <a href={alert.technique.url} target="_blank" rel="noreferrer noopener">
                      {alert.technique.id} {alert.technique.name}
                    </a>
                  ) : (
                    <span className="muted">none (behavioural anomaly)</span>
                  )}
                </td>
              </tr>
              <tr>
                <th scope="row">Analysis</th>
                <td>
                  <Link to={`/analyses/${alert.analysis_id}`} className="mono">
                    {alert.analysis_id.slice(0, 8)}
                  </Link>
                </td>
              </tr>
              <tr>
                <th scope="row">Alert ID</th>
                <td className="mono">{alert.alert_id}</td>
              </tr>
            </tbody>
          </table>
        </Panel>
        <Panel title="Evidence">
          <Value value={alert.evidence} />
        </Panel>
      </div>
      {focusIp ? (
        <Panel title={`Flows involving ${focusIp}`}>
          <FlowBrowser analysisId={alert.analysis_id} initialIp={focusIp} />
        </Panel>
      ) : null}
    </>
  );
}
