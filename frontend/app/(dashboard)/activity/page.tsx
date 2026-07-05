"use client";

import { useEffect, useRef, useState } from "react";
import { CheckCircle2, XCircle, Loader2, Clock, MinusCircle, AlertTriangle } from "lucide-react";
import { api, type ScanRun } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { cn, timeAgo } from "@/lib/utils";

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
                <CardContent className="flex items-center gap-4 p-4">
                  <s.Icon className={cn("h-5 w-5 shrink-0", s.cls, s.spin && "animate-spin")} />
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span className="font-medium">{r.pipeline}</span>
                      <span className={cn("text-xs uppercase tracking-wide", s.cls)}>{s.label}</span>
                    </div>
                    <div className="truncate text-xs text-muted-foreground">
                      {r.program_id}
                      {statsSummary(r.stats) ? ` · ${statsSummary(r.stats)}` : ""}
                      {r.error ? ` · ${r.error}` : ""}
                    </div>
                  </div>
                  <div className="text-right text-xs text-muted-foreground">
                    <div>{duration(r)}</div>
                    <div>{timeAgo(r.started_at)}</div>
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}
