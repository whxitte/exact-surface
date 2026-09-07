"use client";

/**
 * Demo transport — replaces `frontend/lib/transport.ts` at build time.
 *
 * This is the **entire** difference between the demo site and the product. Every page,
 * component, type and endpoint definition is the real thing; only the bytes that would
 * have gone over the network are served from `fixtures.ts` instead.
 *
 * Consequences worth being explicit about:
 *
 * * The demo has **no backend, no database and no API**. There is nothing to attack,
 *   nothing to authenticate against, and no data belonging to anyone. It is a static
 *   site that happens to be the real application.
 * * Writes cannot be "blocked" because there is nowhere for a write to go. Any
 *   mutating call resolves to a friendly refusal object rather than an error, so the
 *   UI stays usable while doing nothing.
 * * The demo cannot drift from the product: if a component starts calling a new
 *   endpoint, the demo build fails to serve it and we notice, rather than the demo
 *   quietly becoming a museum piece.
 *
 * This file must never exist in a product image — `docker/Dockerfile.frontend` copies
 * `frontend/` only, and `tests/unit/test_wiring.py` asserts no Dockerfile references
 * `demo/`.
 */

import * as fx from "./fixtures";

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

/** Small latency so the UI's loading states are visible, as they are in the product. */
const LATENCY_MS = 120;

const delay = <T,>(value: T): Promise<T> =>
  new Promise((resolve) => setTimeout(() => resolve(value), LATENCY_MS));

/** What a mutating call returns. Not an error — the UI should stay pleasant. */
const REFUSAL = {
  status: "demo",
  detail:
    "This is the ExactSurface demo — it is a static site with no backend, so nothing " +
    "can be created or changed. Everything you see is real product output from a " +
    "seeded scan.",
};

function isMutation(opts: RequestInit): boolean {
  const method = (opts.method || "GET").toUpperCase();
  return method !== "GET" && method !== "HEAD";
}

/** Route a path to its fixture. Ordered most-specific first. */
function resolve(path: string): unknown {
  const p = path.split("?")[0].replace(/\/$/, "") || "/";

  // -- program sub-resources ------------------------------------------------
  const prog = p.match(/^\/programs\/([^/]+)(\/.*)?$/);
  if (prog) {
    const sub = (prog[2] || "").replace(/^\//, "");
    switch (sub) {
      case "":                return fx.PROGRAM;
      case "findings":        return fx.FINDINGS;
      case "assets":          return fx.ASSETS;
      case "endpoints":       return fx.ENDPOINTS;
      case "ports":           return fx.PORTS;
      case "secrets":         return fx.SECRETS;
      case "leaks":           return fx.LEAKS;
      case "cves":            return fx.CVES;
      case "deltas":          return fx.DELTAS;
      case "js-files":        return fx.JS_FILES;
      case "scan-runs":       return fx.SCAN_RUNS;
      case "domain-intel":    return fx.DOMAIN_INTEL;
      case "attack-paths":    return fx.ATTACK_PATHS;
      case "attack-surface":  return fx.ATTACK_SURFACE;
      case "correlation":     return fx.CORRELATION;
      case "modules":         return fx.MODULES;
      case "schedule":        return fx.SCHEDULE;
      case "timeouts":        return fx.TIMEOUTS;
      case "alert-policy":    return fx.ALERT_POLICY;
      case "authorization":   return fx.AUTHORIZATION;
    }
    const logs = sub.match(/^scan-runs\/([^/]+)\/logs$/);
    if (logs) return { scan_id: logs[1], lines: fx.SCAN_LOGS };
  }

  switch (p) {
    case "/programs":                  return fx.PROGRAMS;
    case "/stats":                     return fx.STATS;
    case "/activity":                  return fx.ACTIVITY;
    case "/auth/me":                   return fx.ME;
    case "/auth/signup-open":          return { open: false };
    // Playground: the demo has no backend to execute a canvas, so it ships the real
    // node catalogue (so the palette looks exactly like the product) and an empty
    // workflow list. Running is a mutation, so it already returns the refusal object.
    case "/playground/nodes":          return { nodes: fx.PLAYGROUND_NODES };
    case "/playground/workflows":      return { workflows: [] };
    case "/members":                   return fx.MEMBERS;
    case "/members/groups":            return fx.GROUPS;
    case "/members/permissions":       return fx.PERMISSIONS;
    case "/notifications":             return fx.CHANNELS;
    case "/integrations":              return fx.INTEGRATIONS;
    case "/schedule/defaults":         return fx.SCHEDULE_DEFAULTS;
    case "/schedule/timeout-defaults": return fx.TIMEOUT_DEFAULTS;
    case "/schedule/alert-policy":     return fx.ALERT_POLICY_DEFAULTS;
  }

  // An endpoint the fixtures do not cover. Loud on purpose: it means a component
  // started calling something new and the demo needs a fixture for it.
  console.warn(`[demo] no fixture for ${path} — returning an empty result`);
  return [];
}

export async function request<T>(path: string, opts: RequestInit = {}): Promise<T> {
  if (isMutation(opts)) {
    // Login is the one mutation with a real answer: the demo shows the actual login
    // screen, so signing in has to work.
    if (path.startsWith("/auth/login")) return delay(fx.LOGIN as T);
    // A Playground run is queued to the scanning worker and then polled for progress.
    // The demo has neither, and the generic refusal below carries no `run_id`, so the
    // canvas would poll an undefined run until its ten-minute bound expired. Throwing
    // puts the explanation straight into the page's own error banner.
    if (path.startsWith("/playground/run")) {
      await delay(null);
      throw new ApiError(
        501,
        "Running a canvas needs the scanning worker, which this static demo does not have. " +
          "Everything else here is the real thing — drag nodes out of the palette and wire " +
          "them together to see how a workflow is built.",
      );
    }
    return delay(REFUSAL as T);
  }
  return delay(resolve(path) as T);
}

/** Reports are generated server-side in the product; the demo just explains that.
 *  Signature matches the real one so every call site type-checks unchanged. */
export async function downloadReport(_programId: string, _format: string): Promise<void> {
  await delay(null);
  if (typeof window !== "undefined") {
    window.alert(
      "Report generation runs on the server, so it is disabled in this static demo. " +
        "In a real deployment this downloads a PDF or HTML report of every finding.",
    );
  }
}
