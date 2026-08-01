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

/**
 * The HTTP transport every API call goes through.
 *
 * Isolated in its own module for one reason: the read-only demo site replaces *this
 * file only* at build time with a fixture-backed version (`demo/lib/transport.ts`).
 * Everything else — every type, every endpoint in `lib/api.ts`, every component —
 * stays identical, so the demo cannot drift from the product and the product ships
 * none of the demo's code.
 */
export async function request<T>(path: string, opts: RequestInit = {}): Promise<T> {
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
  const filename = match ? match[1] : `exactsurface-report.${format}`;
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
