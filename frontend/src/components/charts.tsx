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

/**
 * Step chart of a time series (packets or bytes per bucket), plain SVG.
 *
 * The API sends only non-empty buckets, so a gap between two buckets means no
 * traffic: the line drops to zero instead of interpolating across the gap.
 * Axis labels are HTML, so they keep their size when the chart is scaled.
 */
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
  const pad = { t: 6, b: 2 };
  const step = bucketSeconds * 1000;
  const times = points.map((p) => new Date(p.t).getTime());
  const t0 = Math.min(...times);
  const t1 = Math.max(...times) + step;
  const peak = Math.max(...points.map((p) => p.value), 1);
  const x = (t: number) => (((t - t0) / Math.max(t1 - t0, 1)) * width).toFixed(1);
  const y = (v: number) => (height - pad.b - (v / peak) * (height - pad.t - pad.b)).toFixed(1);
  const segments: string[] = [`M${x(t0)},${y(0)}`];
  let end = t0;
  points.forEach((p, i) => {
    const start = times[i] ?? t0;
    if (start > end) segments.push(`L${x(end)},${y(0)}`, `L${x(start)},${y(0)}`);
    segments.push(`L${x(start)},${y(p.value)}`, `L${x(start + step)},${y(p.value)}`);
    end = start + step;
  });
  const path = segments.join(" ");
  const area = `${path} L${x(end)},${y(0)} Z`;
  const fmt = unit === "bytes" ? formatBytes : formatNumber;
  const label = (t: number) => new Date(t).toISOString().slice(11, 19);
  const total = points.reduce((s, p) => s + p.value, 0);
  return (
    <figure className="chart">
      <svg
        viewBox={`0 0 ${width} ${height}`}
        preserveAspectRatio="none"
        role="img"
        aria-label={`${unit} per ${bucketSeconds} seconds, peak ${fmt(peak)}`}
      >
        <path d={area} className="chart-area" />
        <path d={path} className="chart-line" />
      </svg>
      <div className="chart-axis">
        <span>{label(t0)}</span>
        <span>peak {fmt(peak)} per bucket</span>
        <span>{label(t1)} UTC</span>
      </div>
      <figcaption className="muted">
        {fmt(total)} {unit === "bytes" ? "" : "packets "}in {bucketSeconds} s buckets
      </figcaption>
    </figure>
  );
}
