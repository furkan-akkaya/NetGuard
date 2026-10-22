import { useState } from "react";
import { api } from "../api";
import { endpoint, formatBytes, formatDuration, formatNumber, formatTime } from "../format";
import { useAsync } from "../hooks";
import { ErrorBox, Loading, Pagination } from "./ui";

const LIMIT = 50;
const STATES = ["", "S0", "S1", "SF", "REJ", "S2", "S3", "RSTO", "RSTR", "RSTOS0", "RSTRH", "SH", "SHR", "OTH"];
const SORTS = [
  ["first_seen", "Oldest first"],
  ["-first_seen", "Newest first"],
  ["-bytes", "Most bytes"],
  ["-packets", "Most packets"],
  ["-duration", "Longest"],
] as const;

/** Server-side filtered, sorted and paginated view of an analysis's stored flows. */
export function FlowBrowser({ analysisId, initialIp = "" }: { analysisId: string; initialIp?: string }) {
  const [proto, setProto] = useState("");
  const [state, setState] = useState("");
  const [ip, setIp] = useState(initialIp);
  const [port, setPort] = useState("");
  const [sort, setSort] = useState<string>("first_seen");
  const [offset, setOffset] = useState(0);
  const portNumber = /^\d{1,5}$/.test(port) ? Number(port) : undefined;
  const flows = useAsync(
    () => api.flows(analysisId, { proto, state, ip: ip.trim(), port: portNumber, sort, limit: LIMIT, offset }),
    [analysisId, proto, state, ip, portNumber, sort, offset],
  );
  const reset = <T,>(set: (v: T) => void) => (v: T) => {
    set(v);
    setOffset(0);
  };

  return (
    <>
      <form className="filters" onSubmit={(e) => e.preventDefault()} aria-label="Flow filters">
        <label>
          Protocol
          <select value={proto} onChange={(e) => reset(setProto)(e.target.value)}>
            <option value="">any</option>
            <option value="tcp">tcp</option>
            <option value="udp">udp</option>
            <option value="icmp">icmp</option>
            <option value="icmp6">icmp6</option>
          </select>
        </label>
        <label>
          State
          <select value={state} onChange={(e) => reset(setState)(e.target.value)}>
            {STATES.map((s) => (
              <option key={s} value={s}>
                {s || "any"}
              </option>
            ))}
          </select>
        </label>
        <label>
          IP address
          <input value={ip} onChange={(e) => reset(setIp)(e.target.value)} placeholder="10.0.0.5" spellCheck={false} />
        </label>
        <label>
          Port
          <input
            value={port}
            onChange={(e) => reset(setPort)(e.target.value)}
            placeholder="443"
            inputMode="numeric"
            aria-invalid={port !== "" && portNumber === undefined}
          />
        </label>
        <label>
          Sort
          <select value={sort} onChange={(e) => reset(setSort)(e.target.value)}>
            {SORTS.map(([v, l]) => (
              <option key={v} value={v}>
                {l}
              </option>
            ))}
          </select>
        </label>
      </form>
      {flows.error ? <ErrorBox error={flows.error} retry={flows.reload} /> : null}
      {flows.loading && !flows.data ? <Loading /> : null}
      {flows.data ? (
        flows.data.total === 0 ? (
          <p className="muted">No flows match.</p>
        ) : (
          <>
            <div className="table-wrap">
              <table className="data">
                <thead>
                  <tr>
                    <th>Originator → responder</th>
                    <th>Proto</th>
                    <th>State</th>
                    <th>History</th>
                    <th className="num">Packets</th>
                    <th className="num">Bytes out / in</th>
                    <th className="num">Duration</th>
                    <th>Start</th>
                  </tr>
                </thead>
                <tbody className={flows.loading ? "stale" : ""}>
                  {flows.data.items.map((f) => (
                    <tr key={f.id}>
                      <td className="mono">
                        {endpoint(f.src_ip, f.src_port)} → {endpoint(f.dst_ip, f.dst_port)}
                      </td>
                      <td>{f.proto}</td>
                      <td className="mono" title={f.end_reason}>
                        {f.state}
                      </td>
                      <td className="mono">{f.history}</td>
                      <td className="num">{formatNumber(f.orig_packets + f.resp_packets)}</td>
                      <td className="num nowrap">
                        {formatBytes(f.orig_bytes)} / {formatBytes(f.resp_bytes)}
                      </td>
                      <td className="num">{formatDuration(f.duration_seconds)}</td>
                      <td className="nowrap">{formatTime(f.first_seen)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pagination total={flows.data.total} limit={LIMIT} offset={offset} onChange={setOffset} />
          </>
        )
      ) : null}
    </>
  );
}
