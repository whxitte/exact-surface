"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  Globe, Plus, CheckCircle2, AlertCircle, ChevronRight, Trash2, Pause, Play,
} from "lucide-react";
import { api, type Program, type Schedule } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { timeAgo, timeUntil } from "@/lib/utils";

export default function ProgramsPage() {
  const [programs, setPrograms] = useState<Program[]>([]);
  const [schedules, setSchedules] = useState<Record<string, Schedule>>({});
  const [apex, setApex] = useState("");
  const [error, setError] = useState("");
  const [adding, setAdding] = useState(false);

  function load() {
    api
      .listPrograms()
      .then((ps) => {
        setPrograms(ps);
        // fetch each program's schedule for the last/next-scan summary
        ps.forEach((p) =>
          api
            .getSchedule(p.program_id)
            .then((s) => setSchedules((prev) => ({ ...prev, [p.program_id]: s })))
            .catch(() => {}),
        );
      })
      .catch((e) => setError(e.message));
  }
  useEffect(load, []);

  function scanSummary(p: Program): string {
    const s = schedules[p.program_id];
    if (!s) return "";
    if (p.enabled === false) return "Monitoring paused";
    if (!s.initial_scan_completed_at && !s.last_full_run) return "First scan pending…";
    const full = s.last_full_run;
    const last = full?.finished_at
      ? `Last scan ${timeAgo(full.finished_at)}`
      : full
        ? `Scan ${full.status}`
        : "Not scanned yet";
    // soonest upcoming phase
    const upcoming = [...s.phases]
      .filter((ph) => ph.next_due_at)
      .sort((a, b) => Date.parse(a.next_due_at!) - Date.parse(b.next_due_at!))[0];
    const next = upcoming ? ` · next ${upcoming.pipeline} ${timeUntil(upcoming.next_due_at)}` : "";
    return last + next;
  }

  async function toggleMonitoring(e: React.MouseEvent, p: Program) {
    e.preventDefault();
    e.stopPropagation();
    try {
      await api.setMonitoring(p.program_id, !p.enabled);
      load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "failed");
    }
  }

  async function removeProgram(e: React.MouseEvent, p: Program) {
    e.preventDefault();
    e.stopPropagation();
    if (!confirm(`Delete ${p.apex_domain} and all of its discovered data? This cannot be undone.`))
      return;
    try {
      await api.deleteProgram(p.program_id);
      load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "failed");
    }
  }

  async function addProgram(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setAdding(true);
    try {
      await api.createProgram(apex.trim());
      setApex("");
      load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "failed to add");
    } finally {
      setAdding(false);
    }
  }

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Programs</h1>
        <p className="text-sm text-muted-foreground">Domains Vantari is watching for you.</p>
      </div>

      <Card>
        <CardContent className="p-5">
          <form onSubmit={addProgram} className="flex items-end gap-3">
            <div className="flex-1">
              <label className="mb-1.5 block text-sm font-medium text-muted-foreground">
                Add a domain
              </label>
              <Input value={apex} onChange={(e) => setApex(e.target.value)}
                placeholder="your-company.com" required />
            </div>
            <Button type="submit" disabled={adding}>
              <Plus className="h-4 w-4" />
              {adding ? "Adding…" : "Add domain"}
            </Button>
          </form>
          {error && <p className="mt-3 text-sm text-severity-critical">{error}</p>}
        </CardContent>
      </Card>

      <div className="space-y-2">
        {programs.length === 0 && (
          <p className="py-8 text-center text-sm text-muted-foreground">
            No programs yet. Add your first domain above.
          </p>
        )}
        {programs.map((p) => (
          <Link key={p.program_id} href={`/programs/${p.program_id}`} className="block">
            <Card className="transition-colors hover:border-primary/40">
              <CardContent className="flex items-center gap-4 p-4">
                <div className="flex h-9 w-9 items-center justify-center rounded-md bg-muted text-muted-foreground">
                  <Globe className="h-4 w-4" />
                </div>
                <div className="min-w-0 flex-1">
                  <div className="font-medium">{p.apex_domain}</div>
                  <div className="truncate text-xs text-muted-foreground">
                    {scanSummary(p) || p.program_id}
                  </div>
                </div>
                {p.enabled === false && (
                  <span className="rounded-full bg-muted px-2 py-0.5 text-xs text-muted-foreground">
                    Paused
                  </span>
                )}
                {p.verified ? (
                  <span className="flex items-center gap-1.5 text-xs text-primary">
                    <CheckCircle2 className="h-4 w-4" /> Verified
                  </span>
                ) : (
                  <span className="flex items-center gap-1.5 text-xs text-severity-medium">
                    <AlertCircle className="h-4 w-4" /> Unverified
                  </span>
                )}
                <button
                  onClick={(e) => toggleMonitoring(e, p)}
                  title={p.enabled === false ? "Resume monitoring" : "Pause monitoring"}
                  className="text-muted-foreground hover:text-foreground"
                >
                  {p.enabled === false ? (
                    <Play className="h-4 w-4" />
                  ) : (
                    <Pause className="h-4 w-4" />
                  )}
                </button>
                <button
                  onClick={(e) => removeProgram(e, p)}
                  title="Delete program"
                  className="text-muted-foreground hover:text-severity-critical"
                >
                  <Trash2 className="h-4 w-4" />
                </button>
                <ChevronRight className="h-4 w-4 text-muted-foreground" />
              </CardContent>
            </Card>
          </Link>
        ))}
      </div>
    </div>
  );
}
