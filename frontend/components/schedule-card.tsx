"use client";

import { useCallback, useEffect, useState } from "react";
import { CalendarClock, Save, ChevronDown, ChevronUp } from "lucide-react";
import { api, type Schedule, type SchedulePhase } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { NumberInput } from "@/components/ui/number-input";
import { Select } from "@/components/ui/select";
import { cn, timeAgo, timeUntil } from "@/lib/utils";

const LABELS: Record<string, string> = {
  ingest: "Subdomain enumeration",
  probe: "HTTP probe",
  crawl: "Crawl",
  content_discovery: "Content discovery",
  port_scan: "Port scan",
  scan: "Vulnerability scan",
  secrets: "Secret scan",
  github_osint: "GitHub OSINT",
  cve_watch: "CVE / KEV watch",
  notify: "Notifications",
};

type Unit = "m" | "h" | "d";
const UNIT_SECS: Record<Unit, number> = { m: 60, h: 3600, d: 86400 };

function toParts(seconds: number): { value: number; unit: Unit } {
  if (seconds % 86400 === 0) return { value: seconds / 86400, unit: "d" };
  if (seconds % 3600 === 0) return { value: seconds / 3600, unit: "h" };
  return { value: Math.max(1, Math.round(seconds / 60)), unit: "m" };
}

export function ScheduleCard({ programId }: { programId: string }) {
  const [sched, setSched] = useState<Schedule | null>(null);
  const [edits, setEdits] = useState<Record<string, number>>({});
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [isOpen, setIsOpen] = useState(false);

  const load = useCallback(() => {
    api.getSchedule(programId).then(setSched).catch((e) => setError(e.message));
  }, [programId]);
  useEffect(load, [load]);

  function setPhaseSeconds(pipeline: string, seconds: number) {
    setEdits((prev) => ({ ...prev, [pipeline]: seconds }));
  }

  async function save() {
    setSaving(true);
    setError("");
    try {
      // send every phase's effective interval, with edits applied
      const overrides: Record<string, number> = {};
      for (const p of sched?.phases ?? [])
        overrides[p.pipeline] = edits[p.pipeline] ?? p.interval_seconds;
      const next = await api.setSchedule(programId, overrides);
      setSched(next);
      setEdits({});
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed");
    } finally {
      setSaving(false);
    }
  }

  if (!sched) return null;
  const full = sched.last_full_run;
  const dirty = Object.keys(edits).length > 0;

  return (
    <Card>
      <CardContent className="p-5">
        <div
          onClick={() => setIsOpen(!isOpen)}
          className="flex items-center justify-between cursor-pointer select-none"
        >
          <div className="flex items-center gap-2">
            <CalendarClock className="h-4 w-4 text-primary" />
            <h2 className="text-sm font-semibold">Scan schedule</h2>
          </div>
          <ChevronDown
            className={cn(
              "h-4 w-4 text-muted-foreground hover:text-foreground transition-transform duration-300",
              isOpen && "rotate-180"
            )}
          />
        </div>

        <div
          className="grid transition-[grid-template-rows] duration-300 ease-in-out"
          style={{ gridTemplateRows: isOpen ? "1fr" : "0fr" }}
        >
          <div className="overflow-hidden">
            <div className="space-y-4 pt-4">
              {/* last full run */}
              <div className="grid grid-cols-2 gap-3 text-sm sm:grid-cols-3">
                <Stat label="Last full scan started" value={full ? timeAgo(full.started_at) : "never"} />
                <Stat
                  label="Last full scan finished"
                  value={
                    full
                      ? full.finished_at
                        ? timeAgo(full.finished_at)
                        : `running (${full.status})`
                      : "—"
                  }
                />
                <Stat
                  label="Initial scan"
                  value={sched.initial_scan_completed_at ? "complete" : "pending / first run"}
                />
              </div>

              {/* per-phase breakdown */}
              <div className="overflow-x-auto">
                <table className="w-full min-w-[520px] text-sm">
                  <thead>
                    <tr className="border-b border-border text-left text-xs text-muted-foreground">
                      <th className="py-2 font-medium">Phase</th>
                      <th className="py-2 font-medium">Every</th>
                      <th className="py-2 font-medium">Last run</th>
                      <th className="py-2 font-medium">Next scan</th>
                    </tr>
                  </thead>
                  <tbody>
                    {sched.phases.map((p) => (
                      <PhaseRow
                        key={p.pipeline}
                        phase={p}
                        seconds={edits[p.pipeline] ?? p.interval_seconds}
                        onChange={(s) => setPhaseSeconds(p.pipeline, s)}
                      />
                    ))}
                  </tbody>
                </table>
              </div>

              <div className="flex items-center gap-3">
                <Button onClick={save} disabled={!dirty || saving}>
                  <Save className="h-4 w-4" /> {saving ? "Saving…" : "Save schedule"}
                </Button>
                {error && <span className="text-sm text-severity-critical">{error}</span>}
              </div>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="font-medium">{value}</div>
    </div>
  );
}

function PhaseRow({
  phase,
  seconds,
  onChange,
}: {
  phase: SchedulePhase;
  seconds: number;
  onChange: (seconds: number) => void;
}) {
  const { value, unit } = toParts(seconds);
  return (
    <tr className="border-b border-border/60">
      <td className="py-2">
        {LABELS[phase.pipeline] ?? phase.pipeline}
        {phase.source !== "default" && (
          <span className="ml-2 rounded-full bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground">
            {phase.source}
          </span>
        )}
      </td>
      <td className="py-2">
        <div className="flex items-center gap-1">
          <NumberInput
            min={1}
            value={value}
            onChange={(val) => onChange(Math.max(1, val) * UNIT_SECS[unit])}
          />
          <Select
            value={unit}
            onChange={(e) => onChange(value * UNIT_SECS[e.target.value as Unit])}
            className="h-8 w-16"
          >
            <option value="m">min</option>
            <option value="h">hr</option>
            <option value="d">day</option>
          </Select>
        </div>
      </td>
      <td className="py-2 text-muted-foreground">{timeAgo(phase.last_run_at)}</td>
      <td className="py-2 text-muted-foreground">{timeUntil(phase.next_due_at)}</td>
    </tr>
  );
}
