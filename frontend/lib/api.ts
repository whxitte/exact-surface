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
  const body = text ? JSON.parse(text) : null;
  if (!res.ok) {
    throw new ApiError(res.status, body?.detail || res.statusText);
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
export interface Verification { method: string; token: string; instructions: string }

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

  listPrograms: () => request<Program[]>("/programs"),
  createProgram: (apex_domain: string) =>
    request<Program>("/programs", json({ apex_domain })),
  getProgram: (id: string) => request<Program>(`/programs/${id}`),
  requestVerify: (id: string, method: string) =>
    request<Verification>(`/programs/${id}/verify/request?method=${method}`, { method: "POST" }),
  checkVerify: (id: string) =>
    request<{ verified: boolean; detail: string }>(`/programs/${id}/verify/check`, { method: "POST" }),
  createAuthorization: (id: string) =>
    request<unknown>(`/programs/${id}/authorization`, json({})),
  triggerScan: (id: string) =>
    request<{ status: string }>(`/programs/${id}/scan`, { method: "POST" }),

  listFindings: (id: string, q: Record<string, string> = {}) => {
    const qs = new URLSearchParams(q).toString();
    return request<Finding[]>(`/programs/${id}/findings${qs ? `?${qs}` : ""}`);
  },
  listAssets: (id: string) => request<Asset[]>(`/programs/${id}/assets`),
  listSecrets: (id: string) => request<Record<string, unknown>[]>(`/programs/${id}/secrets`),
  listDeltas: (id: string) => request<Record<string, unknown>[]>(`/programs/${id}/deltas`),
};
