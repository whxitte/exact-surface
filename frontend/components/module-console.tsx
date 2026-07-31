"use client";

import { useEffect, useRef, useState } from "react";
import { Play, TerminalSquare, Loader2, Lock, ChevronDown, AlertTriangle } from "lucide-react";
import { api, type ModuleInfo, type ScanRun } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";

/**
 * Developer console — run any single module on demand and watch it.
 *
 * The product runs modules two ways: the whole ordered pipeline, or the scheduler's
 * cadence. Neither helps when you are building a module and want to see what it does
 * right now. This is the third way: pick one, run it, read its log.
 *
 * It calls the same dispatch path the scheduler uses, so what you see here is what
 * production does — including a module reporting itself skipped because its dependency
 * is off. That is the honest result, not a limitation of the console.
 */
export function ModuleConsole({ programId }: { programId: string }) {
  const [modules, setModules] = useState<ModuleInfo[]>([]);
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [runs, setRuns] = useState<ScanRun[]>([]);
  const [logsFor, setLogsFor] = useState<string>("");
  const [logs, setLogs] = useState<string[]>([]);
  const logBox = useRef<HTMLPreElement>(null);

  useEffect(() => {
    api
      .getModules(programId)
      .then((r) => setModules(r.modules))
      .catch((e) => setError(e instanceof Error ? e.message : "could not load modules"));
  }, [programId]);

  // Poll recent runs while the panel is open so a module's outcome shows up here
  // rather than making the developer go and find it in the Activity tab.
  useEffect(() => {
    if (!open) return;
    let live = true;
    const tick = async () => {
      try {
        const r = await api.listScanRuns(programId);
        if (live) setRuns(r.slice(0, 12));
      } catch {
        /* the panel is a convenience; a failed poll must not throw at the user */
      }
    };
    tick();
    const id = setInterval(tick, 3000);
    return () => {
      live = false;
      clearInterval(id);
    };
  }, [open, programId]);

  // Stream the selected run's logs.
  useEffect(() => {
    if (!logsFor) return;
    let live = true;
    const tick = async () => {
      try {
        const r = await api.scanLogs(programId, logsFor);
        if (!live) return;
        setLogs(r.lines);
        const el = logBox.current;
        if (el) el.scrollTop = el.scrollHeight;
      } catch {
        /* ignore */
      }
    };
    tick();
    const id = setInterval(tick, 2000);
    return () => {
      live = false;
      clearInterval(id);
    };
  }, [logsFor, programId]);

  async function run(m: ModuleInfo) {
    setBusy(m.name);
    setError("");
    setNotice("");
    try {
      const res = await api.runModule(programId, m.name);
      setNotice(res.detail);
      // Attach to the run as soon as the worker registers it.
      setTimeout(async () => {
        try {
          const r = await api.listScanRuns(programId);
          const mine = r.find((x) => x.pipeline === m.name);
          if (mine) setLogsFor(mine.scan_id);
        } catch {
          /* ignore */
        }
      }, 1200);
    } catch (e) {
      setError(e instanceof Error ? e.message : "could not start the module");
    } finally {
      setBusy("");
    }
  }

  if (modules.length === 0) return null;

  const runByModule = new Map(runs.map((r) => [r.pipeline, r]));

  return (
    <Card className="border-dashed">
      <CardContent className="p-5">
        <div
          onClick={() => setOpen(!open)}
          className="flex cursor-pointer select-none items-center justify-between"
        >
          <div className="flex items-center gap-2">
            <TerminalSquare className="h-4 w-4 text-primary" />
            <h2 className="text-sm font-semibold">Developer console</h2>
            <span className="rounded bg-muted px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-muted-foreground">
              run one module
            </span>
          </div>
          <ChevronDown
            className={cn(
              "h-4 w-4 text-muted-foreground transition-transform duration-300",
              open && "rotate-180",
            )}
          />
        </div>

        <div
          className="grid transition-[grid-template-rows] duration-300 ease-in-out"
          style={{ gridTemplateRows: open ? "1fr" : "0fr" }}
        >
          <div className="overflow-hidden">
            <div className="space-y-4 pt-4">
              <p className="text-xs text-muted-foreground">
                Runs a single module immediately, through the same dispatcher the scheduler
                uses — same scope checks, same authorization gate, same rate limits. A module
                whose dependency is switched off will report itself skipped here too, because
                that is what it would do in production.
              </p>

              {notice && (
                <p className="rounded-md border border-primary/30 bg-primary/5 p-2 text-xs text-primary">
                  {notice}
                </p>
              )}
              {error && <p className="text-sm text-severity-critical">{error}</p>}

              <div className="grid gap-1.5 sm:grid-cols-2">
                {modules.map((m) => {
                  const last = runByModule.get(m.name);
                  const running = last?.status === "running" || last?.status === "queued";
                  return (
                    <div
                      key={m.name}
                      className="flex items-start gap-2 rounded-md border border-border p-2.5"
                    >
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-1.5">
                          <span className="font-mono text-xs font-medium">{m.name}</span>
                          {!m.enabled && (
                            <span
                              title={m.skip_reason}
                              className="inline-flex items-center gap-1 rounded bg-muted px-1 py-0.5 text-[10px] text-muted-foreground"
                            >
                              <Lock className="h-2.5 w-2.5" /> off
                            </span>
                          )}
                          {last && (
                            <span
                              className={cn(
                                "rounded px-1 py-0.5 text-[10px] uppercase",
                                last.status === "success" && "bg-severity-low/15 text-severity-low",
                                last.status === "failed" &&
                                  "bg-severity-critical/15 text-severity-critical",
                                last.status === "skipped" && "bg-muted text-muted-foreground",
                                running && "bg-primary/15 text-primary",
                              )}
                            >
                              {last.status}
                            </span>
                          )}
                        </div>
                        <p className="mt-0.5 line-clamp-1 text-[11px] text-muted-foreground">
                          {m.label}
                        </p>
                        {last?.error && (
                          <p className="mt-1 flex items-start gap-1 text-[11px] text-severity-critical">
                            <AlertTriangle className="mt-0.5 h-2.5 w-2.5 shrink-0" />
                            {last.error}
                          </p>
                        )}
                      </div>
                      <div className="flex shrink-0 gap-1">
                        {last && (
                          <button
                            onClick={() => setLogsFor(last.scan_id)}
                            title="Show this run's log"
                            className={cn(
                              "rounded border border-border px-1.5 py-1 text-[10px] hover:bg-muted",
                              logsFor === last.scan_id && "border-primary text-primary",
                            )}
                          >
                            log
                          </button>
                        )}
                        <button
                          onClick={() => run(m)}
                          disabled={busy === m.name || running}
                          title={`Run ${m.name} now`}
                          className="rounded border border-border p-1.5 text-muted-foreground hover:bg-muted hover:text-foreground disabled:opacity-40"
                        >
                          {busy === m.name || running ? (
                            <Loader2 className="h-3 w-3 animate-spin" />
                          ) : (
                            <Play className="h-3 w-3" />
                          )}
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>

              {logsFor && (
                <div>
                  <div className="mb-1 flex items-center justify-between">
                    <span className="font-mono text-[11px] text-muted-foreground">
                      log · {logsFor.slice(0, 12)}
                    </span>
                    <button
                      onClick={() => {
                        setLogsFor("");
                        setLogs([]);
                      }}
                      className="text-[11px] text-muted-foreground hover:text-foreground"
                    >
                      close
                    </button>
                  </div>
                  <pre
                    ref={logBox}
                    className="max-h-72 overflow-auto rounded-md border border-border bg-black/40 p-3 font-mono text-[11px] leading-relaxed text-muted-foreground"
                  >
                    {logs.length ? logs.join("\n") : "waiting for output…"}
                  </pre>
                </div>
              )}
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
