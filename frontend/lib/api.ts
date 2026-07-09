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
  severity: string;
  state: string;
  is_new: boolean;
  first_seen?: string;
  description?: string;
  references?: string[];
}
export interface Asset {
  fingerprint: string;
  hostname: string;
  resolved_ips: string[];
  ip_class?: string | null;
  is_ephemeral: boolean;
  monitored?: boolean;
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

  listFindings: (id: string, q: Record<string, string> = {}) => {
    const qs = new URLSearchParams(q).toString();
    return request<Finding[]>(`/programs/${id}/findings${qs ? `?${qs}` : ""}`);
  },
  listAssets: (id: string) => request<Asset[]>(`/programs/${id}/assets`),
  listSecrets: (id: string) => request<Secret[]>(`/programs/${id}/secrets`),
  listDeltas: (id: string) => request<Record<string, unknown>[]>(`/programs/${id}/deltas`),

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
