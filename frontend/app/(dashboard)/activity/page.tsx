"use client";

import { Fragment, useEffect, useRef, useState } from "react";
import {
  CheckCircle2, XCircle, Loader2, Clock, MinusCircle, AlertTriangle,
  ChevronRight, ChevronDown, Terminal, Ban,
} from "lucide-react";
import { api, type ScanRun, type ScanStage } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { cn, timeAgo } from "@/lib/utils";
import { pipelineDesc, pipelineLabel } from "@/lib/pipelines";
import { getToken } from "@/lib/auth";

const STATUS: Record<string, { label: string; cls: string; Icon: React.ElementType; spin?: boolean }> = {
  running: { label: "running", cls: "text-severity-medium", Icon: Loader2, spin: true },
  stalled: { label: "stalled", cls: "text-severity-high", Icon: AlertTriangle },
  success: { label: "success", cls: "text-primary", Icon: CheckCircle2 },
  failed: { label: "failed", cls: "text-severity-critical", Icon: XCircle },
  queued: { label: "queued", cls: "text-severity-low", Icon: Clock },
  skipped: { label: "skipped", cls: "text-muted-foreground", Icon: MinusCircle },
};

function duration(r: ScanRun): string {
  if (!r.started_at) return "";
  const end = r.finished_at ? new Date(r.finished_at).getTime() : Date.now();
  const secs = Math.max(0, Math.round((end - new Date(r.started_at).getTime()) / 1000));
  return `${secs}s`;
}

function statsSummary(stats?: Record<string, number>): string {
  if (!stats) return "";
  return Object.entries(stats)
    .filter(([, v]) => v > 0)
    .map(([k, v]) => `${v} ${k.replace(/_/g, " ")}`)
    .join(" · ");
}

// n8n-style horizontal stepper: one node per pipeline stage, connectors between.
const STAGE_DOT: Record<string, string> = {
  success: "border-primary bg-primary text-background",
  running: "border-severity-medium bg-severity-medium/20 text-severity-medium",
  failed: "border-severity-critical bg-severity-critical/20 text-severity-critical",
  skipped: "border-muted bg-transparent text-muted-foreground",
  queued: "border-muted bg-transparent text-muted-foreground",
};

function stageStat(st: ScanStage): string {
  if (st.note) return st.note;
  return statsSummary(st.stats);
}

// A disabled optional module (toggle off) — rendered distinctly from a normal skip.
const isDisabled = (s: ScanStage) => s.note === "not enabled — turn on in settings";

function StageStepper({ stages }: { stages: ScanStage[] }) {
  // stages that need an explicit explanation (skipped reason / failure)
  const explain = stages.filter((s) => s.status === "skipped" || s.status === "failed");
  return (
    <div className="mt-3 space-y-2 overflow-x-auto">
      <div className="flex min-w-[720px] items-center pb-1">
        {stages.map((st, i) => {
          const dot = STAGE_DOT[st.status] || STAGE_DOT.queued;
          const done = st.status === "success";
          const tip = `${pipelineLabel(st.name)} — ${pipelineDesc(st.name)}${
            stageStat(st) ? `\n${stageStat(st)}` : ""
          }`;
          return (
            <Fragment key={st.name}>
              {i > 0 && (
                <div
                  className={cn(
                    "h-px flex-1",
                    stages[i - 1].status === "success" ? "bg-primary" : "bg-border",
                  )}
                />
              )}
              <div className="flex flex-col items-center gap-1" title={tip}>
                <span
                  className={cn(
                    "flex h-5 w-5 items-center justify-center rounded-full border text-[10px] font-semibold",
                    dot,
                  )}
                >
                  {st.status === "running" ? (
                    <Loader2 className="h-3 w-3 animate-spin" />
                  ) : st.status === "failed" ? (
                    <XCircle className="h-3 w-3" />
                  ) : isDisabled(st) ? (
                    <Ban className="h-3 w-3 opacity-50" />
                  ) : st.status === "skipped" ? (
                    <MinusCircle className="h-3 w-3" />
                  ) : done ? (
                    <CheckCircle2 className="h-3 w-3" />
                  ) : (
                    i + 1
                  )}
                </span>
                <span
                  className={cn(
                    "text-[10px] leading-none",
                    st.status === "queued" || st.status === "skipped"
                      ? "text-muted-foreground"
                      : "text-foreground",
                  )}
                >
                  {pipelineLabel(st.name)}
                </span>
              </div>
            </Fragment>
          );
        })}
      </div>

      {/* Spell out why any stage was skipped or failed — no silent "success". */}
      {explain.length > 0 && (
        <div className="space-y-0.5 pt-1">
          {explain.map((st) => (
            <div key={st.name} className="flex items-start gap-1.5 text-[11px]">
              <span
                className={cn(
                  "shrink-0 uppercase tracking-wide",
                  st.status === "failed" ? "text-severity-critical" : "text-muted-foreground",
                )}
              >
                {pipelineLabel(st.name)} {isDisabled(st) ? "disabled" : st.status}
              </span>
              {st.note && !isDisabled(st) && (
                <span className="text-muted-foreground">— {st.note}</span>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// Live log tail for one scan — polls while the panel is open.
//
// Scrolling follows the terminal convention: it sticks to the bottom while you are
// there, but the moment you scroll up to read something it stops yanking you back.
// Scroll to the bottom again and it resumes following.
function ScanLogs({ programId, scanId, active }: { programId: string; scanId: string; active: boolean }) {
  const [lines, setLines] = useState<string[]>([]);
  const [err, setErr] = useState(false);
  const [following, setFollowing] = useState(true);
  const boxRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    let stopped = false;
    let timer: ReturnType<typeof setInterval> | null = null;
    async function poll() {
      try {
        const data = await api.scanLogs(programId, scanId);
        if (!stopped) {
          setLines(data.lines);
          setErr(false);
        }
      } catch {
        if (!stopped) setErr(true);
      }
    }
    poll();
    // keep polling only while the run is still active; otherwise fetch once.
    if (active) timer = setInterval(poll, 2000);
    return () => {
      stopped = true;
      if (timer) clearInterval(timer);
    };
  }, [programId, scanId, active]);

  useEffect(() => {
    if (following && boxRef.current) boxRef.current.scrollTop = boxRef.current.scrollHeight;
  }, [lines, following]);

  function onScroll() {
    const el = boxRef.current;
    if (!el) return;
    // 24px of slack so a near-bottom position still counts as "following".
    const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 24;
    setFollowing(atBottom);
  }

  return (
    <div className="mt-3">
      <div className="mb-1 flex items-center gap-1.5 text-[11px] uppercase tracking-wide text-muted-foreground">
        <Terminal className="h-3.5 w-3.5" /> Live logs
        {lines.length > 0 && <span className="normal-case">({lines.length} lines)</span>}
        {!following && (
          <button
            onClick={() => {
              setFollowing(true);
              if (boxRef.current) boxRef.current.scrollTop = boxRef.current.scrollHeight;
            }}
            className="ml-auto rounded border border-border px-1.5 py-0.5 text-[10px] normal-case text-primary hover:bg-muted"
          >
            Jump to latest
          </button>
        )}
      </div>
      <div
        ref={boxRef}
        onScroll={onScroll}
        className="max-h-96 overflow-auto rounded-md border border-border bg-background/60 p-2 font-mono text-[11px] leading-relaxed"
      >
        {lines.length === 0 ? (
          <span className="text-muted-foreground">
            {err ? "Logs unavailable (needs Redis / live worker)." : "No log lines yet…"}
          </span>
        ) : (
          lines.map((l, i) => (
            <div key={i} className="whitespace-pre-wrap break-all text-foreground/80">
              {l}
            </div>
          ))
        )}
      </div>
    </div>
  );
}

const runKey = (r: ScanRun) => String(r.started_at || r.created_at || "");
const sortRuns = (rs: ScanRun[]) => [...rs].sort((a, b) => (runKey(a) < runKey(b) ? 1 : -1));

export default function ActivityPage() {
  const [runs, setRuns] = useState<ScanRun[]>([]);
  const [live, setLive] = useState(true);
  const timer = useRef<ReturnType<typeof setInterval> | null>(null);

  // Baseline: poll every 3s (always on — survives refresh, works with no websocket).
  useEffect(() => {
    let stopped = false;
    async function poll() {
      try {
        const data = await api.activity();
        if (!stopped) {
          setRuns(data);
          setLive(true);
        }
      } catch {
        if (!stopped) setLive(false);
      }
    }
    poll();
    timer.current = setInterval(poll, 3000);
    return () => {
      stopped = true;
      if (timer.current) clearInterval(timer.current);
    };
  }, []);

  // Accelerator: a websocket pushes each ScanRun update instantly. Purely
  // additive — any failure is ignored and the poll above keeps the feed current.
  useEffect(() => {
    if (typeof window === "undefined") return;
    let ws: WebSocket | null = null;
    try {
      const token = getToken();
      if (!token) return;
      const proto = window.location.protocol === "https:" ? "wss" : "ws";
      ws = new WebSocket(`${proto}://${window.location.host}/api/ws/activity?token=${token}`);
      ws.onmessage = (ev) => {
        const msg = JSON.parse(ev.data);
        if (msg.type === "snapshot") {
          setRuns(sortRuns(msg.runs as ScanRun[]));
        } else if (msg.type === "run") {
          const incoming = msg.run as ScanRun;
          setRuns((prev) => {
            const rest = prev.filter((r) => r.scan_id !== incoming.scan_id);
            return sortRuns([incoming, ...rest]).slice(0, 60);
          });
        }
        setLive(true);
      };
    } catch {
      // ignore — the 3s poll remains the source of truth
    }
    return () => ws?.close();
  }, []);

  const [expanded, setExpanded] = useState<Record<string, boolean>>({});

  // "Stalled" = no activity, not just long-running. A healthy full scan can run
  // ~90 min (two nuclei batches over many hosts); the worker heartbeats updated_at
  // every ~45s while a stage is live, so we key off last-activity, not total age.
  function effStatus(r: ScanRun): string {
    if (r.status !== "running") return r.status;
    const last = r.updated_at || r.started_at;
    if (!last) return "running";
    const idleMin = (Date.now() - new Date(last).getTime()) / 60000;
    return idleMin > 8 ? "stalled" : "running";
  }
  const running = runs.filter((r) => effStatus(r) === "running").length;

  const isActive = (r: ScanRun) => r.status === "running" || r.status === "queued";
  // Full runs auto-open while active; otherwise honor the user's toggle (default closed).
  const isExpanded = (r: ScanRun) => expanded[r.scan_id] ?? isActive(r);
  const toggle = (r: ScanRun) =>
    setExpanded((e) => ({ ...e, [r.scan_id]: !(e[r.scan_id] ?? isActive(r)) }));

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-semibold tracking-tight">
            Activity
            <span className="relative flex h-2.5 w-2.5">
              <span
                className={cn(
                  "absolute inline-flex h-full w-full rounded-full opacity-75",
                  live ? "animate-ping bg-primary" : "bg-muted",
                )}
              />
              <span className={cn("relative inline-flex h-2.5 w-2.5 rounded-full", live ? "bg-primary" : "bg-muted")} />
            </span>
          </h1>
          <p className="text-sm text-muted-foreground">
            Live workflow feed · updates every 3s{running ? ` · ${running} running now` : ""}
          </p>
        </div>
      </div>

      {runs.length === 0 ? (
        <p className="py-10 text-center text-sm text-muted-foreground">
          No activity yet. Trigger a scan or wait for the scheduler’s next cycle.
        </p>
      ) : (
        <div className="space-y-2">
          {runs.map((r) => {
            const s = STATUS[effStatus(r)] || STATUS.queued;
            const isFull = r.pipeline === "full";

            // Compact one-line row for the scheduler's per-pipeline cadence runs,
            // so they don't drown out the full-scan stepper (dedupes the feed).
            if (!isFull) {
              return (
                <div
                  key={r.scan_id}
                  className="flex items-center gap-3 rounded-lg border border-border/60 px-4 py-2 text-sm"
                >
                  <s.Icon className={cn("h-4 w-4 shrink-0", s.cls, s.spin && "animate-spin")} />
                  <span className="font-medium">{pipelineLabel(r.pipeline)}</span>
                  <span className={cn("text-[10px] uppercase tracking-wide", s.cls)}>{s.label}</span>
                  <span className="min-w-0 flex-1 truncate text-xs text-muted-foreground">
                    {statsSummary(r.stats) || (r.note ? `skipped — ${r.note}` : pipelineDesc(r.pipeline))}
                    {r.error ? ` · ⚠ ${r.error}` : ""}
                  </span>
                  <span className="shrink-0 font-mono text-[10px] text-muted-foreground opacity-60">
                    {r.program_id}
                  </span>
                  <span className="shrink-0 text-xs text-muted-foreground">{timeAgo(r.started_at)}</span>
                </div>
              );
            }

            // Full scan: expandable card — header always; stepper + live logs on expand.
            const open = isExpanded(r);
            return (
              <Card key={r.scan_id}>
                <CardContent className="p-4">
                  <button
                    onClick={() => toggle(r)}
                    className="flex w-full items-center gap-4 text-left"
                    aria-expanded={open}
                  >
                    {open ? (
                      <ChevronDown className="h-4 w-4 shrink-0 text-muted-foreground" />
                    ) : (
                      <ChevronRight className="h-4 w-4 shrink-0 text-muted-foreground" />
                    )}
                    <s.Icon className={cn("h-5 w-5 shrink-0", s.cls, s.spin && "animate-spin")} />
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <span className="font-medium">{pipelineLabel(r.pipeline)}</span>
                        <span className={cn("text-xs uppercase tracking-wide", s.cls)}>{s.label}</span>
                      </div>
                      <div className="truncate text-xs text-muted-foreground">
                        {pipelineDesc(r.pipeline)}
                        {statsSummary(r.stats) ? ` · ${statsSummary(r.stats)}` : ""}
                      </div>
                      {r.error && (
                        <div className="mt-0.5 truncate text-xs text-severity-critical">⚠ {r.error}</div>
                      )}
                    </div>
                    <div className="shrink-0 text-right text-xs text-muted-foreground">
                      <div>{duration(r)}</div>
                      <div>{timeAgo(r.started_at)}</div>
                      <div className="font-mono opacity-60">{r.program_id}</div>
                    </div>
                  </button>
                  {open && (
                    <>
                      {r.stages && r.stages.length > 0 && <StageStepper stages={r.stages} />}
                      <ScanLogs programId={r.program_id} scanId={r.scan_id} active={isActive(r)} />
                    </>
                  )}
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}
