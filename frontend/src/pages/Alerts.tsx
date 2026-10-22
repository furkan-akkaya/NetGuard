import { useSearchParams } from "react-router";
import { api } from "../api";
import { AlertTable } from "../components/AlertTable";
import { Empty, ErrorBox, Loading, Pagination, Panel } from "../components/ui";
import { useAsync } from "../hooks";

const LIMIT = 50;
const FILTERS = ["severity", "min_severity", "rule_id", "ip", "q", "analysis_id", "sort"] as const;

export function Alerts() {
  // Filters live in the URL: views are shareable and survive a reload.
  const [params, setParams] = useSearchParams();
  const get = (k: string) => params.get(k) ?? "";
  const offset = Number(params.get("offset") ?? "0") || 0;
  const query = Object.fromEntries(FILTERS.map((k) => [k, get(k)]));
  const rules = useAsync(() => api.rules(), []);
  const alerts = useAsync(
    () => api.alerts({ ...query, sort: query.sort || "-first_seen", limit: LIMIT, offset }),
    [params.toString()],
  );
  const set = (key: string, value: string) => {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    if (key !== "offset") next.delete("offset");
    setParams(next, { replace: true });
  };

  return (
    <>
      <h1>Alerts</h1>
      <Panel title="Filters">
        <form className="filters" onSubmit={(e) => e.preventDefault()} aria-label="Alert filters">
          <label>
            Severity
            <select value={get("min_severity")} onChange={(e) => set("min_severity", e.target.value)}>
              <option value="">any</option>
              <option value="MEDIUM">medium and high</option>
              <option value="HIGH">high only</option>
            </select>
          </label>
          <label>
            Rule
            <select value={get("rule_id")} onChange={(e) => set("rule_id", e.target.value)}>
              <option value="">any</option>
              {rules.data?.map((r) => (
                <option key={r.rule_id} value={r.rule_id}>
                  {r.rule_id} {r.title}
                </option>
              ))}
            </select>
          </label>
          <label>
            IP (source or target)
            <input value={get("ip")} onChange={(e) => set("ip", e.target.value.trim())} spellCheck={false} />
          </label>
          <label>
            Text
            <input value={get("q")} onChange={(e) => set("q", e.target.value)} maxLength={200} placeholder="search summaries" />
          </label>
          <label>
            Sort
            <select value={get("sort") || "-first_seen"} onChange={(e) => set("sort", e.target.value)}>
              <option value="-first_seen">Newest first</option>
              <option value="first_seen">Oldest first</option>
              <option value="-severity">Most severe</option>
              <option value="rule_id">Rule</option>
            </select>
          </label>
          {get("analysis_id") ? (
            <button type="button" className="btn" onClick={() => set("analysis_id", "")}>
              Analysis {get("analysis_id").slice(0, 8)} ✕
            </button>
          ) : null}
        </form>
      </Panel>
      <Panel title={alerts.data ? `${alerts.data.total.toLocaleString("en-US")} alerts` : "Alerts"}>
        {alerts.error ? <ErrorBox error={alerts.error} retry={alerts.reload} /> : null}
        {alerts.loading && !alerts.data ? <Loading /> : null}
        {alerts.data && alerts.data.total === 0 ? (
          <Empty title="No alerts match">Change the filters, or analyse a capture first.</Empty>
        ) : null}
        {alerts.data && alerts.data.total > 0 ? (
          <>
            <AlertTable alerts={alerts.data.items} showAnalysis />
            <Pagination total={alerts.data.total} limit={LIMIT} offset={offset} onChange={(o) => set("offset", String(o))} />
          </>
        ) : null}
      </Panel>
    </>
  );
}
