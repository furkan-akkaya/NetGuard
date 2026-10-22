import { Link } from "react-router";
import type { Alert } from "../api";
import { endpoint, formatTime } from "../format";
import { SeverityBadge } from "./ui";

/** Alert rows linking to the detail page. All text is rendered as text (React escapes it). */
export function AlertTable({ alerts, showAnalysis = false }: { alerts: Alert[]; showAnalysis?: boolean }) {
  return (
    <div className="table-wrap">
      <table className="data">
        <thead>
          <tr>
            <th>Severity</th>
            <th>Alert</th>
            <th>Source → target</th>
            <th>Rule</th>
            <th>First seen</th>
            {showAnalysis ? <th>Analysis</th> : null}
          </tr>
        </thead>
        <tbody>
          {alerts.map((a) => (
            <tr key={a.id}>
              <td>
                <SeverityBadge severity={a.severity} />
              </td>
              <td className="wrap">
                <Link to={`/alerts/${a.id}`}>{a.title}</Link>
                <div className="muted clamp">{a.summary}</div>
              </td>
              <td className="mono">
                {endpoint(a.src)}
                {a.dst ? ` → ${a.dst}` : ""}
              </td>
              <td className="mono nowrap">{a.rule_id}</td>
              <td className="nowrap">{formatTime(a.first_seen)}</td>
              {showAnalysis ? (
                <td>
                  <Link to={`/analyses/${a.analysis_id}`} className="mono">
                    {a.analysis_id.slice(0, 8)}
                  </Link>
                </td>
              ) : null}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
