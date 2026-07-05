"use client";

import { Fragment, useEffect, useRef, useState } from "react";
import { CheckCircle2, XCircle, Loader2, Clock, MinusCircle, AlertTriangle } from "lucide-react";
import { api, type ScanRun, type ScanStage } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { cn, timeAgo } from "@/lib/utils";
import { pipelineDesc, pipelineLabel } from "@/lib/pipelines";

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

function StageStepper({ stages }: { stages: ScanStage[] }) {
  // stages that need an explicit explanation (skipped reason / failure)
  const explain = stages.filter((s) => s.status === "skipped" || s.status === "failed");
  return (
    <div className="mt-3 space-y-2">
      <div className="flex items-center">
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
                {pipelineLabel(st.name)} {st.status}
              </span>
              {st.note && <span className="text-muted-foreground">— {st.note}</span>}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default function ActivityPage() {
  const [runs, setRuns] = useState<ScanRun[]>([]);
  const [live, setLive] = useState(true);
  const timer = useRef<ReturnType<typeof setInterval> | null>(null);

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
    timer.current = setInterval(poll, 3000); // live update, survives refresh (reads DB)
    return () => {
      stopped = true;
      if (timer.current) clearInterval(timer.current);
    };
  }, []);

  // A run stuck "running" for >20 min is almost certainly orphaned (worker died).
  function effStatus(r: ScanRun): string {
    if (r.status !== "running" || !r.started_at) return r.status;
    const ageMin = (Date.now() - new Date(r.started_at).getTime()) / 60000;
    return ageMin > 20 ? "stalled" : "running";
  }
  const running = runs.filter((r) => effStatus(r) === "running").length;

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
            return (
              <Card key={r.scan_id}>
                <CardContent className="p-4">
                  <div className="flex items-center gap-4">
                    <s.Icon className={cn("h-5 w-5 shrink-0", s.cls, s.spin && "animate-spin")} />
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <span className="font-medium">{pipelineLabel(r.pipeline)}</span>
                        <span className={cn("text-xs uppercase tracking-wide", s.cls)}>{s.label}</span>
                      </div>
                      <div className="truncate text-xs text-muted-foreground">
                        {pipelineDesc(r.pipeline) || r.program_id}
                        {statsSummary(r.stats) ? ` · ${statsSummary(r.stats)}` : ""}
                      </div>
                      {(r.note || r.error) && (
                        <div
                          className={cn(
                            "mt-0.5 truncate text-xs",
                            r.error ? "text-severity-critical" : "text-muted-foreground",
                          )}
                        >
                          {r.error ? `⚠ ${r.error}` : `skipped — ${r.note}`}
                        </div>
                      )}
                    </div>
                    <div className="shrink-0 text-right text-xs text-muted-foreground">
                      <div>{duration(r)}</div>
                      <div>{timeAgo(r.started_at)}</div>
                      <div className="font-mono opacity-60">{r.program_id}</div>
                    </div>
                  </div>
                  {r.stages && r.stages.length > 0 && <StageStepper stages={r.stages} />}
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}
