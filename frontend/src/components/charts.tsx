import { formatBytes, formatNumber } from "../format";

export interface BarItem {
  label: string;
  value: number;
}

/** Horizontal bars. Semantically a table, so screen readers get the numbers. */
export function BarList({
  items,
  valueLabel = "Count",
  format = formatNumber,
  max = 10,
}: {
  items: BarItem[];
  valueLabel?: string;
  format?: (n: number) => string;
  max?: number;
}) {
  const shown = items.slice(0, max);
  if (!shown.length) return <p className="muted">No data.</p>;
  const peak = Math.max(...shown.map((i) => i.value), 1);
  return (
    <table className="bars">
      <thead className="sr-only">
        <tr>
          <th>Item</th>
          <th>{valueLabel}</th>
        </tr>
      </thead>
      <tbody>
        {shown.map((item) => (
          <tr key={item.label}>
            <th scope="row" className="mono" title={item.label}>
              {item.label}
            </th>
            <td>
              <div className="bar-track">
                <div className="bar-fill" style={{ width: `${(100 * item.value) / peak}%` }} />
              </div>
            </td>
            <td className="num">{format(item.value)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export interface Point {
  t: string; // ISO start of the bucket
  value: number;
}

/** Area chart of a time series (packets or bytes per bucket), plain SVG. */
export function TimeSeries({
  points,
  bucketSeconds,
  unit = "packets",
  height = 160,
}: {
  points: Point[];
  bucketSeconds: number;
  unit?: "packets" | "bytes";
  height?: number;
}) {
  if (points.length === 0) return <p className="muted">No traffic.</p>;
  const width = 640;
  const pad = { l: 8, r: 8, t: 10, b: 22 };
  const times = points.map((p) => new Date(p.t).getTime());
  const t0 = Math.min(...times);
  const t1 = Math.max(...times) + bucketSeconds * 1000;
  const peak = Math.max(...points.map((p) => p.value), 1);
  const x = (t: number) => pad.l + ((t - t0) / Math.max(t1 - t0, 1)) * (width - pad.l - pad.r);
  const y = (v: number) => height - pad.b - (v / peak) * (height - pad.t - pad.b);
  // Each value holds for its whole bucket, so the last one extends to the bucket's end.
  const last = points[points.length - 1]?.value ?? 0;
  const path =
    points.map((p, i) => `${i ? "L" : "M"}${x(times[i] ?? t0).toFixed(1)},${y(p.value).toFixed(1)}`).join(" ") +
    ` L${x(t1).toFixed(1)},${y(last).toFixed(1)}`;
  const area = `${path} L${x(t1).toFixed(1)},${height - pad.b} L${x(t0).toFixed(1)},${height - pad.b} Z`;
  const fmt = unit === "bytes" ? formatBytes : formatNumber;
  const label = (t: number) => new Date(t).toISOString().slice(11, 19);
  const total = points.reduce((s, p) => s + p.value, 0);
  return (
    <figure className="chart">
      <svg viewBox={`0 0 ${width} ${height}`} role="img" aria-label={`${unit} per ${bucketSeconds} seconds, peak ${fmt(peak)}`}>
        <path d={area} className="chart-area" />
        <path d={path} className="chart-line" />
        <text x={pad.l} y={height - 6} className="chart-axis">
          {label(t0)}
        </text>
        <text x={width - pad.r} y={height - 6} className="chart-axis" textAnchor="end">
          {label(t1)} UTC
        </text>
        <text x={width - pad.r} y={pad.t + 4} className="chart-axis" textAnchor="end">
          peak {fmt(peak)}
        </text>
      </svg>
      <figcaption className="muted">
        {fmt(total)} {unit === "bytes" ? "" : "packets "}in {points.length} buckets of {bucketSeconds} s
      </figcaption>
    </figure>
  );
}
