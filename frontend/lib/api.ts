"use client";

import { clearSession, getToken } from "./auth";

const BASE = "/api";

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function request<T>(path: string, opts: RequestInit = {}): Promise<T> {
  const token = getToken();
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(opts.headers as Record<string, string>),
  };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const res = await fetch(BASE + path, { ...opts, headers });

  if (res.status === 401) {
    clearSession();
    if (typeof window !== "undefined" && !path.startsWith("/auth/")) {
      window.location.href = "/login";
    }
    throw new ApiError(401, "unauthorized");
  }
  if (res.status === 204) return undefined as T;

  const text = await res.text();
  let body: unknown = null;
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      // Non-JSON response (e.g. a proxy/gateway error page) — surface it readably.
      if (!res.ok) throw new ApiError(res.status, text.slice(0, 200) || res.statusText);
    }
  }
  if (!res.ok) {
    const detail = (body as { detail?: string } | null)?.detail;
    throw new ApiError(res.status, detail || res.statusText);
  }
  return body as T;
}

// -- types -------------------------------------------------------------------
export interface TokenResponse { access_token: string; tenant_id: string }
export interface Program {
  program_id: string;
  apex_domain: string;
  verified: boolean;
  enabled: boolean;
  scan_shared_infra?: boolean;
  enabled_modules?: string[];
  verification_method?: string | null;
  created_at?: string;
}
export interface Finding {
  fingerprint: string;
  check_id: string;
  module: string;
  name: string;
  location: string;
  locator?: string; // what matched (e.g. detected tech for Wappalyzer)
  severity: string;
  state: string;
  is_new: boolean;
  first_seen?: string;
  last_seen?: string; // last scan that re-confirmed it (still live)
  description?: string;
  references?: string[];
  cvss?: number | null;
  raw?: Record<string, unknown>; // full tool output (nuclei request/response/curl/tags)
}
export interface Asset {
  fingerprint: string;
  hostname: string;
  resolved_ips: string[];
  ip_class?: string | null;
  is_ephemeral: boolean;
  monitored?: boolean;
  dns_records?: Record<string, string[]>; // a/aaaa/cname/ns/mx/txt
  takeover_risk?: string | null; // service name if takeover-vulnerable
  first_seen?: string; // when the subdomain first appeared on the internet
  last_seen?: string; // last time it was observed alive (stops advancing when it goes down)
  gone?: boolean; // not re-observed in the latest scan sweep
}
export interface Endpoint {
  fingerprint: string;
  url: string;
  method: string;
  status_code?: number | null;
  title?: string | null;
  tech: string[];
  source?: string; // probe | crawl | feroxbuster
  first_seen?: string;
  last_seen?: string; // last scan that re-confirmed it live
  gone?: boolean; // not re-observed in the latest sweep
}
export interface Port {
  fingerprint: string;
  ip: string;
  port: number;
  protocol: string;
  service?: string | null;
  product?: string | null;
  version?: string | null;
  first_seen?: string;
  last_seen?: string; // last scan that re-confirmed the port open
  gone?: boolean; // not re-observed in the latest port sweep
}
export interface Leak {
  fingerprint: string;
  kind: string;
  masked: string;
  source: string;
  repo?: string | null;
  url?: string | null;
  severity: string;
  first_seen?: string;
}
export interface Stats {
  programs: number;
  assets: number;
  endpoints: number;
  secrets: number;
  findings: number;
  new_findings: number;
  findings_by_severity: Record<string, number>;
}
export interface ScanStage {
  name: string;
  status: string; // queued | running | success | failed | skipped
  started_at?: string;
  finished_at?: string;
  stats?: Record<string, number>;
  note?: string; // why skipped / short explanation
}
export interface ScanRun {
  scan_id: string;
  program_id: string;
  pipeline: string;
  status: string; // queued | running | success | failed | skipped
  created_at?: string;
  started_at?: string;
  finished_at?: string;
  updated_at?: string; // last heartbeat/save — liveness signal
  error?: string;
  note?: string; // why skipped (single-pipeline runs)
  stats?: Record<string, number>;
  stages?: ScanStage[];
}
export interface Verification { method: string; token: string; instructions: string }
export interface Channel {
  channel_id: string;
  name: string;
  type: string;
  enabled: boolean;
  min_severity: string;
  config: Record<string, string>;
}
export interface Secret {
  fingerprint: string;
  kind: string;
  masked: string;
  source_locator: string;
  severity: string;
}
export interface Cve {
  fingerprint: string;
  cve_id: string;
  cpe: string;
  asset_fingerprint: string;
  cvss?: number | null;
  on_kev: boolean;
  confidence: string; // low | medium | high
  severity: string;
  first_seen?: string;
  last_seen?: string; // last scan that re-confirmed the match
}
export interface CorrelatedIssue {
  host: string;
  risk_score: number;
  highest_severity: string;
  is_chain: boolean;
  signals: string[];
}
export interface Correlation {
  count: number;
  chains: number;
  issues: CorrelatedIssue[];
}
export interface AlertPolicyValues {
  finding_min_severity: string;
  alert_findings: boolean;
  alert_secrets: boolean;
  alert_leaks: boolean;
  alert_cves: boolean;
  cve_min_cvss: number;
  alert_new_assets: boolean;
  alert_new_ports: boolean;
  port_filter: string;
}
export interface AlertPolicy {
  alert_policy: Partial<AlertPolicyValues>; // this scope's own overrides
  effective?: AlertPolicyValues; // defaults←tenant←program (program endpoint only)
  defaults: AlertPolicyValues;
  tenant_defaults?: Partial<AlertPolicyValues>; // program endpoint only
  severities: string[];
}
export interface SchedulePhase {
  pipeline: string;
  interval_seconds: number;
  last_run_at?: string | null;
  next_due_at?: string | null;
  source: "program" | "tenant" | "default";
}
export interface Schedule {
  program_id: string;
  initial_scan_completed_at?: string | null;
  last_full_run?: {
    scan_id: string;
    status: string;
    started_at?: string | null;
    finished_at?: string | null;
  } | null;
  phases: SchedulePhase[];
}
export interface ScheduleDefaults {
  cadence_overrides: Record<string, number>;
  pipelines: { pipeline: string; label: string; default_seconds: number }[];
  min_interval_seconds?: number;
}
export interface TimeoutStage {
  stage: string;
  timeout_seconds: number;
  source: "program" | "tenant" | "default";
}
export interface TimeoutConfig {
  program_id: string;
  stages: TimeoutStage[];
}
export interface TimeoutDefaults {
  timeout_overrides: Record<string, number>;
  stages: { stage: string; label: string; default_seconds: number }[];
  min_seconds?: number;
  max_seconds?: number;
}
export interface SurfaceCount {
  total: number;
  [severity: string]: number;
}
export interface SurfaceChange {
  opened: number;
  resolved: number;
}
export interface SurfaceSeriesPoint {
  at: string;
  total: number;
  assets: number;
  endpoints: number;
  ports: number;
  findings: number;
  secrets: number;
  leaks: number;
}
export interface SurfaceEvent {
  kind: "opened" | "resolved";
  type: string;
  label: string;
  at: string;
  severity: string | null;
}
export interface AttackSurface {
  generated_at: string;
  latest_scan_at: string | null;
  previous_scan_at: string | null;
  scan_count: number;
  current: {
    total: number;
    assets: SurfaceCount;
    endpoints: SurfaceCount;
    ports: SurfaceCount;
    findings: SurfaceCount;
    secrets: SurfaceCount;
    leaks: SurfaceCount;
  };
  change: {
    opened: number;
    resolved: number;
    net: number;
    assets: SurfaceChange;
    endpoints: SurfaceChange;
    ports: SurfaceChange;
    findings: SurfaceChange;
    secrets: SurfaceChange;
    leaks: SurfaceChange;
  };
  series: SurfaceSeriesPoint[];
  recent: SurfaceEvent[];
}
export interface Delta {
  kind: string; // status_change | title_change | tech_change | cert_change | new_port | new_asset
  before?: string | null;
  after?: string | null;
  observed_at?: string;
  asset_fingerprint?: string;
}
export interface Integration {
  name: string;
  label: string;
  help: string;
  secret: boolean;
  configured: boolean;
  masked: string;
}

const json = (b: unknown) => ({ method: "POST", body: JSON.stringify(b) });

export const api = {
  signup: (email: string, password: string, tenant_name: string) =>
    request<TokenResponse>("/auth/signup", json({ email, password, tenant_name })),
  login: (email: string, password: string) =>
    request<TokenResponse>("/auth/login", json({ email, password })),
  me: () => request<{ tenant_id: string; role: string; auth: string }>("/auth/me"),
  createApiKey: (name: string) =>
    request<{ key_id: string; name: string; api_key: string; prefix: string }>(
      "/auth/api-keys",
      json({ name }),
    ),

  stats: () => request<Stats>("/stats"),
  activity: () => request<ScanRun[]>("/activity"),
  scanLogs: (programId: string, scanId: string) =>
    request<{ scan_id: string; lines: string[] }>(
      `/programs/${programId}/scan-runs/${scanId}/logs`,
    ),

  listPrograms: () => request<Program[]>("/programs"),
  createProgram: (apex_domain: string) =>
    request<Program>("/programs", json({ apex_domain })),
  getProgram: (id: string) => request<Program>(`/programs/${id}`),
  deleteProgram: (id: string) => request<void>(`/programs/${id}`, { method: "DELETE" }),
  setMonitoring: (id: string, enabled: boolean) =>
    request<{ program_id: string; enabled: boolean }>(
      `/programs/${id}/monitoring?enabled=${enabled}`,
      { method: "POST" },
    ),
  setAssetMonitoring: (id: string, fingerprint: string, enabled: boolean) =>
    request<{ fingerprint: string; monitored: boolean }>(
      `/programs/${id}/assets/${fingerprint}/monitoring?enabled=${enabled}`,
      { method: "POST" },
    ),
  requestVerify: (id: string, method: string) =>
    request<Verification>(`/programs/${id}/verify/request?method=${method}`, { method: "POST" }),
  checkVerify: (id: string) =>
    request<{ verified: boolean; detail: string }>(`/programs/${id}/verify/check`, { method: "POST" }),
  createAuthorization: (id: string) =>
    request<unknown>(`/programs/${id}/authorization`, json({})),
  getAuthorization: (id: string) =>
    request<{ apex_verified: boolean; revoked?: boolean; authorized_by?: string }>(
      `/programs/${id}/authorization`,
    ),
  triggerScan: (id: string) =>
    request<{ status: string; detail?: string }>(`/programs/${id}/scan`, { method: "POST" }),
  setScanSharedInfra: (id: string, value: boolean) =>
    request<{ program_id: string; scan_shared_infra: boolean }>(
      `/programs/${id}/scan-config?scan_shared_infra=${value}`,
      { method: "POST" },
    ),
  setModules: (id: string, enabled: string[]) =>
    request<{ program_id: string; enabled_modules: string[] }>(`/programs/${id}/modules`, {
      method: "POST",
      body: JSON.stringify(enabled),
    }),
  getSchedule: (id: string) => request<Schedule>(`/programs/${id}/schedule`),
  setSchedule: (id: string, overrides: Record<string, number>) =>
    request<Schedule>(`/programs/${id}/schedule`, json({ overrides })),
  getScheduleDefaults: () => request<ScheduleDefaults>("/schedule/defaults"),
  setScheduleDefaults: (overrides: Record<string, number>) =>
    request<ScheduleDefaults>("/schedule/defaults", json({ overrides })),
  getTimeouts: (id: string) => request<TimeoutConfig>(`/programs/${id}/timeouts`),
  setTimeouts: (id: string, overrides: Record<string, number>) =>
    request<TimeoutConfig>(`/programs/${id}/timeouts`, json({ overrides })),
  getTimeoutDefaults: () => request<TimeoutDefaults>("/schedule/timeout-defaults"),
  setTimeoutDefaults: (overrides: Record<string, number>) =>
    request<TimeoutDefaults>("/schedule/timeout-defaults", json({ overrides })),
  getAlertPolicy: (id: string) => request<AlertPolicy>(`/programs/${id}/alert-policy`),
  setAlertPolicy: (id: string, policy: Partial<AlertPolicyValues>) =>
    request<AlertPolicy>(`/programs/${id}/alert-policy`, json({ policy })),
  getAlertPolicyDefaults: () => request<AlertPolicy>("/schedule/alert-policy"),
  setAlertPolicyDefaults: (policy: Partial<AlertPolicyValues>) =>
    request<AlertPolicy>("/schedule/alert-policy", json({ policy })),

  listFindings: (id: string, q: Record<string, string> = {}) => {
    const qs = new URLSearchParams(q).toString();
    return request<Finding[]>(`/programs/${id}/findings${qs ? `?${qs}` : ""}`);
  },
  getAttackSurface: (id: string) => request<AttackSurface>(`/programs/${id}/attack-surface`),
  listAssets: (id: string) => request<Asset[]>(`/programs/${id}/assets`),
  listEndpoints: (id: string) => request<Endpoint[]>(`/programs/${id}/endpoints`),
  listPorts: (id: string) => request<Port[]>(`/programs/${id}/ports`),
  listLeaks: (id: string) => request<Leak[]>(`/programs/${id}/leaks`),
  listCves: (id: string) => request<Cve[]>(`/programs/${id}/cves`),
  getCorrelation: (id: string) => request<Correlation>(`/programs/${id}/correlation`),
  listSecrets: (id: string) => request<Secret[]>(`/programs/${id}/secrets`),
  listDeltas: (id: string) => request<Delta[]>(`/programs/${id}/deltas`),

  listChannels: () => request<Channel[]>("/notifications"),
  createChannel: (body: {
    name: string;
    type: string;
    min_severity: string;
    config: Record<string, string>;
  }) => request<Channel>("/notifications", json(body)),
  deleteChannel: (id: string) =>
    request<void>(`/notifications/${id}`, { method: "DELETE" }),

  listIntegrations: () => request<Integration[]>("/integrations"),
  setIntegration: (name: string, value: string) =>
    request<void>(`/integrations/${name}`, { method: "PUT", body: JSON.stringify({ value }) }),
  clearIntegration: (name: string) =>
    request<void>(`/integrations/${name}`, { method: "DELETE" }),
};

/** Fetch a report with auth and trigger a browser download. */
export async function downloadReport(programId: string, format: string): Promise<void> {
  const token = getToken();
  const res = await fetch(`${BASE}/programs/${programId}/reports?format=${format}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) throw new ApiError(res.status, "report generation failed");
  const blob = await res.blob();
  const disposition = res.headers.get("content-disposition") || "";
  const match = disposition.match(/filename="(.+?)"/);
  const filename = match ? match[1] : `vantari-report.${format}`;
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
