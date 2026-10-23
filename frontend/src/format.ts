// Display helpers. Pure functions, unit-tested in format.test.ts.

import type { Stats } from "./api";

const UNITS = ["B", "KB", "MB", "GB", "TB"];

export function formatBytes(n: number): string {
  if (!Number.isFinite(n) || n < 0) return "–";
  let value = n;
  let unit = 0;
  while (value >= 1000 && unit < UNITS.length - 1) {
    value /= 1000;
    unit += 1;
  }
  return `${unit === 0 ? value : value.toFixed(value < 10 ? 2 : value < 100 ? 1 : 0)} ${UNITS[unit]}`;
}

export function formatNumber(n: number): string {
  return Number.isFinite(n) ? n.toLocaleString("en-US") : "–";
}

export function formatDuration(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) return "–";
  if (seconds < 1) return `${Math.round(seconds * 1000)} ms`;
  if (seconds < 60) return `${seconds.toFixed(seconds < 10 ? 2 : 1)} s`;
  const m = Math.floor(seconds / 60);
  const s = Math.round(seconds % 60);
  if (m < 60) return `${m} min ${s} s`;
  return `${Math.floor(m / 60)} h ${m % 60} min`;
}

/** ISO timestamp -> "2025-10-09 08:53:20 UTC" (captures are compared across machines, so UTC). */
export function formatTime(iso: string | null | undefined): string {
  if (!iso) return "–";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return `${d.toISOString().replace("T", " ").slice(0, 19)} UTC`;
}

export function timeAgo(iso: string | null | undefined, now: number = Date.now()): string {
  if (!iso) return "–";
  const diff = (now - new Date(iso).getTime()) / 1000;
  if (!Number.isFinite(diff)) return "–";
  if (diff < 60) return "just now";
  if (diff < 3600) return `${Math.floor(diff / 60)} min ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)} h ago`;
  return `${Math.floor(diff / 86400)} d ago`;
}

export function endpoint(ip: string | null, port?: number | null): string {
  if (!ip) return "?";
  const host = ip.includes(":") ? `[${ip}]` : ip;
  return port === undefined || port === null ? ip : `${host}:${port}`;
}

/** Turn evidence keys like "distinct_ports" into "Distinct ports". */
export function humanize(key: string): string {
  const words = key.replace(/_/g, " ").trim();
  return words.charAt(0).toUpperCase() + words.slice(1);
}

/** Detectors that dropped state because a table was full (same rule as stats.state_losses). */
export function stateLosses(stats: Stats): [string, number][] {
  return Object.entries(stats.detectors ?? {})
    .map(([name, counters]): [string, number] => [
      name,
      Object.entries(counters)
        .filter(([key]) => key.startsWith("evicted") || key.startsWith("untracked"))
        .reduce((sum, [, n]) => sum + n, 0),
    ])
    .filter(([, n]) => n > 0);
}
