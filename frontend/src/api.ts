// Typed client for the NetGuard REST API v1 (see docs/API.md and /api/v1/openapi.json).
// Same origin only. When the server requires a token, it is kept in sessionStorage
// (cleared when the tab closes) and sent as a bearer header; no cookies are used.

export const API = "/api/v1";
const TOKEN_KEY = "netguard.token";

export type Severity = "LOW" | "MEDIUM" | "HIGH";
export type Status = "queued" | "running" | "done" | "failed" | "cancelled";

export interface Page<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export interface Capture {
  id: string;
  filename: string;
  sha256: string;
  size_bytes: number;
  format: "pcap" | "pcapng";
  created_at: string;
}

export interface AnalysisSummary {
  id: string;
  capture_id: string;
  status: Status;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  error: string | null;
  attempts: number;
  netguard_version: string;
  profile_id: string | null;
  alert_count: number;
  flow_count: number;
  flows_truncated: boolean;
}

export interface FlowRecord {
  id?: number;
  proto: string;
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  first_seen: string;
  last_seen: string;
  duration_seconds: number;
  state: string;
  history: string;
  orig_packets: number;
  orig_bytes: number;
  orig_payload_bytes: number;
  resp_packets: number;
  resp_bytes: number;
  resp_payload_bytes: number;
  retransmissions: number;
  seq_gaps: number;
  end_reason: string;
}

export interface Endpoint {
  ip: string;
  bytes_sent: number;
  bytes_received: number;
  packets_sent: number;
  packets_received: number;
  flows_originated: number;
  flows_responded: number;
}

export interface Stats {
  packets: number;
  bytes: number;
  decode_errors: number;
  unsupported_linktype_frames: Record<string, number>;
  fragments: number;
  first_seen: string | null;
  last_seen: string | null;
  duration_seconds: number;
  protocols: Record<string, number>;
  packet_sizes: Record<string, number>;
  timeseries: { bucket_seconds: number; buckets: { start: string; packets: number; bytes: number }[] };
  flows: {
    total: number;
    evicted: number;
    states: Record<string, number>;
    retransmissions: number;
    top_services: { service: string; flows: number }[];
    top_by_bytes: FlowRecord[];
  };
  endpoints: { approximate: boolean; top_by_bytes: Endpoint[] };
}

export interface Analysis extends AnalysisSummary {
  config: Record<string, unknown>;
  capture_info: { format: string; linktypes: number[]; truncated: boolean; skipped_blocks: number } | null;
  stats: Stats | null;
}

export interface Technique {
  id: string;
  name: string;
  url: string;
}

export interface Alert {
  id: number;
  analysis_id: string;
  schema_version: string;
  alert_id: string;
  rule_id: string;
  detector: string;
  title: string;
  severity: Severity;
  first_seen: string;
  last_seen: string;
  src: string | null;
  dst: string | null;
  summary: string;
  technique: Technique | null;
  evidence: Record<string, unknown>;
}

export interface Rule {
  rule_id: string;
  detector: string;
  title: string;
  technique: string | null;
  enabled: boolean;
  settings: Record<string, unknown>;
  doc: string;
}

export interface Profile {
  id: string;
  name: string;
  description: string;
  config: Record<string, Record<string, unknown> | unknown>;
  created_at: string;
  updated_at: string;
}

export interface Summary {
  captures: number;
  capture_bytes: number;
  analyses: Record<Status, number>;
  alerts: Record<Severity, number>;
  alerts_by_rule: { rule_id: string; count: number }[];
  recent_alerts: Alert[];
  recent_analyses: AnalysisSummary[];
}

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export function getToken(): string | null {
  try {
    return sessionStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

export function setToken(token: string | null): void {
  try {
    if (token) sessionStorage.setItem(TOKEN_KEY, token);
    else sessionStorage.removeItem(TOKEN_KEY);
  } catch {
    // Storage unavailable (private mode): the token lives only for this page.
  }
}

function headers(extra: Record<string, string> = {}): Record<string, string> {
  const token = getToken();
  return token ? { ...extra, Authorization: `Bearer ${token}` } : extra;
}

async function errorFrom(res: Response): Promise<ApiError> {
  let message = `${res.status} ${res.statusText}`;
  try {
    const body = (await res.json()) as { detail?: unknown };
    if (typeof body.detail === "string") message = body.detail;
    else if (Array.isArray(body.detail)) message = body.detail.map((d: { msg?: string }) => d.msg ?? "").join("; ");
  } catch {
    // not JSON: keep the status line
  }
  return new ApiError(res.status, message);
}

export async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(API + path, {
    ...init,
    headers: headers((init.headers as Record<string, string>) ?? {}),
  });
  if (!res.ok) throw await errorFrom(res);
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

type Query = Record<string, string | number | boolean | null | undefined>;

export function qs(params: Query): string {
  const search = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== "") search.set(k, String(v));
  }
  const s = search.toString();
  return s ? `?${s}` : "";
}

const json = (body: unknown): RequestInit => ({
  body: JSON.stringify(body),
  headers: { "Content-Type": "application/json" },
});

export const api = {
  summary: () => request<Summary>("/summary"),
  rules: () => request<Rule[]>("/rules"),
  captures: (q: Query = {}) => request<Page<Capture>>(`/captures${qs(q)}`),
  capture: (id: string) => request<Capture>(`/captures/${encodeURIComponent(id)}`),
  deleteCapture: (id: string) => request<void>(`/captures/${encodeURIComponent(id)}`, { method: "DELETE" }),
  analyses: (q: Query = {}) => request<Page<AnalysisSummary>>(`/analyses${qs(q)}`),
  analysis: (id: string) => request<Analysis>(`/analyses/${encodeURIComponent(id)}`),
  analyse: (captureId: string, profileId: string | null, config: Record<string, unknown> = {}) =>
    request<Analysis>(`/captures/${encodeURIComponent(captureId)}/analyses`, {
      method: "POST",
      ...json({ profile_id: profileId, config }),
    }),
  cancel: (id: string) => request<Analysis>(`/analyses/${encodeURIComponent(id)}/cancel`, { method: "POST" }),
  flows: (analysisId: string, q: Query = {}) =>
    request<Page<FlowRecord>>(`/analyses/${encodeURIComponent(analysisId)}/flows${qs(q)}`),
  alerts: (q: Query = {}) => request<Page<Alert>>(`/alerts${qs(q)}`),
  alert: (id: number | string) => request<Alert>(`/alerts/${encodeURIComponent(String(id))}`),
  profiles: () => request<Profile[]>("/profiles"),
  createProfile: (p: Pick<Profile, "name" | "description" | "config">) =>
    request<Profile>("/profiles", { method: "POST", ...json(p) }),
  updateProfile: (id: string, p: Pick<Profile, "name" | "description" | "config">) =>
    request<Profile>(`/profiles/${encodeURIComponent(id)}`, { method: "PUT", ...json(p) }),
  deleteProfile: (id: string) => request<void>(`/profiles/${encodeURIComponent(id)}`, { method: "DELETE" }),
};

/** Upload a capture as the raw request body, reporting progress (0..1). XHR because fetch has no upload progress. */
export function uploadCapture(file: File, onProgress: (fraction: number) => void): Promise<Capture> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", `${API}/captures${qs({ filename: file.name })}`);
    xhr.setRequestHeader("Content-Type", "application/octet-stream");
    const token = getToken();
    if (token) xhr.setRequestHeader("Authorization", `Bearer ${token}`);
    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable) onProgress(e.loaded / e.total);
    };
    xhr.onload = () => {
      let body: { detail?: string } | Capture | null = null;
      try {
        body = JSON.parse(xhr.responseText) as Capture | { detail?: string };
      } catch {
        body = null;
      }
      if (xhr.status === 200 || xhr.status === 201) resolve(body as Capture);
      else reject(new ApiError(xhr.status, (body as { detail?: string } | null)?.detail ?? `upload failed (${xhr.status})`));
    };
    xhr.onerror = () => reject(new ApiError(0, "network error during upload"));
    xhr.send(file);
  });
}

/** Download an authenticated export (NDJSON, CSV, HTML report) as a file. */
export async function download(path: string, filename: string): Promise<void> {
  const res = await fetch(API + path, { headers: headers() });
  if (!res.ok) throw await errorFrom(res);
  const url = URL.createObjectURL(await res.blob());
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
