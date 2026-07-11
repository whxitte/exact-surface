"use client";

import { useEffect, useMemo, useState } from "react";
import { ChevronDown, ExternalLink } from "lucide-react";
import { api, type Finding } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { SeverityBadge } from "@/components/ui/badge";
import { SEVERITIES, severityRank } from "@/lib/severity";
import { cn } from "@/lib/utils";
import { timeAgo } from "@/lib/utils";

interface Row extends Finding {
  program_id: string;
  apex: string;
}

const CONFIRMED = new Set(["confirmed", "regressed"]);

export default function FindingsPage() {
  const [rows, setRows] = useState<Row[]>([]);
  const [filter, setFilter] = useState<string>("all");
  const [program, setProgram] = useState<string>("all");
  const [open, setOpen] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const programs = useMemo(() => {
    const seen = new Map<string, string>();
    rows.forEach((r) => seen.set(r.program_id, r.apex));
    return [...seen.entries()].sort((a, b) => a[1].localeCompare(b[1]));
  }, [rows]);

  useEffect(() => {
    (async () => {
      try {
        const progs = await api.listPrograms();
        const all: Row[] = [];
        for (const p of progs) {
          const fs = await api.listFindings(p.program_id);
          fs.forEach((f) => all.push({ ...f, program_id: p.program_id, apex: p.apex_domain }));
        }
        all.sort((a, b) => severityRank(a.severity) - severityRank(b.severity));
        setRows(all);
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  const shown = useMemo(
    () =>
      rows.filter(
        (r) =>
          (filter === "all" || r.severity === filter) &&
          (program === "all" || r.program_id === program),
      ),
    [rows, filter, program],
  );

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Findings</h1>
        <p className="text-sm text-muted-foreground">Everything an attacker could act on, ranked.</p>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        {["all", ...SEVERITIES].map((s) => (
          <button
            key={s}
            onClick={() => setFilter(s)}
            className={cn(
              "rounded-full border px-3 py-1 text-xs capitalize transition-colors",
              filter === s
                ? "border-primary bg-primary/10 text-primary"
                : "border-border text-muted-foreground hover:text-foreground",
            )}
          >
            {s}
          </button>
        ))}
        {programs.length > 1 && (
          <select
            value={program}
            onChange={(e) => setProgram(e.target.value)}
            className="ml-auto h-8 rounded-md border border-border bg-background px-2 text-xs"
          >
            <option value="all">All programs</option>
            {programs.map(([id, apex]) => (
              <option key={id} value={id}>
                {apex}
              </option>
            ))}
          </select>
        )}
      </div>

      {loading ? (
        <p className="py-8 text-center text-sm text-muted-foreground">Loading…</p>
      ) : shown.length === 0 ? (
        <p className="py-8 text-center text-sm text-muted-foreground">No findings match.</p>
      ) : (
        <div className="space-y-2">
          {shown.map((f) => {
            const key = `${f.program_id}-${f.fingerprint}`;
            return (
              <FindingCard
                key={key}
                f={f}
                open={open === key}
                onToggle={() => setOpen(open === key ? null : key)}
              />
            );
          })}
        </div>
      )}
    </div>
  );
}

function FindingCard({ f, open, onToggle }: { f: Row; open: boolean; onToggle: () => void }) {
  const raw = (f.raw || {}) as Record<string, unknown>;
  const info = (raw.info || {}) as Record<string, unknown>;
  const tags = (info.tags as string[] | undefined) || [];
  const confirmed = CONFIRMED.has((f.state || "").toLowerCase());
  const str = (k: string) => (typeof raw[k] === "string" ? (raw[k] as string) : "");
  const curl = str("curl-command");
  const request = str("request");
  const response = str("response");
  const extracted = f.locator || ((raw["extracted-results"] as string[] | undefined) || []).join(", ");

  return (
    <Card className="overflow-hidden">
      <button
        onClick={onToggle}
        className="flex w-full items-center gap-3 p-4 text-left transition-colors hover:bg-muted/30"
      >
        <ChevronDown
          className={cn("h-4 w-4 shrink-0 text-muted-foreground transition-transform", open && "rotate-180")}
        />
        <SeverityBadge severity={f.severity} />
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="truncate font-medium">{f.name}</span>
            <span
              className={cn(
                "shrink-0 rounded-full px-1.5 py-0.5 text-[10px] uppercase",
                confirmed
                  ? "bg-severity-high/15 text-severity-high"
                  : "bg-muted text-muted-foreground",
              )}
            >
              {confirmed ? "confirmed" : "unconfirmed"}
            </span>
          </div>
          <div className="truncate font-mono text-xs text-muted-foreground">{f.location}</div>
        </div>
        {f.is_new && <span className="shrink-0 text-xs text-primary">NEW</span>}
        <span className="hidden shrink-0 rounded bg-muted px-1.5 py-0.5 font-mono text-[11px] text-muted-foreground sm:inline">
          {f.module}
        </span>
        <span className="hidden shrink-0 text-xs text-muted-foreground md:inline">{f.apex}</span>
      </button>

      {open && (
        <CardContent className="space-y-4 border-t border-border bg-muted/10 p-4 text-sm">
          {tags.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {tags.map((t) => (
                <span key={t} className="rounded bg-muted px-1.5 py-0.5 text-[11px] text-muted-foreground">
                  {t}
                </span>
              ))}
            </div>
          )}

          {f.description && <p className="text-muted-foreground">{f.description}</p>}

          <dl className="grid gap-x-6 gap-y-2 sm:grid-cols-2">
            <Meta label="Matched at" mono>{f.location}</Meta>
            <Meta label="Template / check">{f.check_id}</Meta>
            {extracted && <Meta label="Detected" mono>{extracted}</Meta>}
            {f.cvss != null && <Meta label="CVSS">{f.cvss.toFixed(1)}</Meta>}
            <Meta label="First found">{timeAgo(f.first_seen)}</Meta>
            <Meta label="Last seen">{timeAgo(f.last_seen)}</Meta>
          </dl>

          {(f.references?.length ?? 0) > 0 && (
            <div>
              <div className="mb-1 text-xs uppercase tracking-wide text-muted-foreground">References</div>
              <ul className="space-y-0.5">
                {f.references!.map((r) => (
                  <li key={r}>
                    <a
                      href={r}
                      target="_blank"
                      rel="noreferrer"
                      className="inline-flex items-center gap-1 break-all text-xs text-primary hover:underline"
                    >
                      {r} <ExternalLink className="h-3 w-3 shrink-0" />
                    </a>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {curl && <Pre label="cURL">{curl}</Pre>}
          {request && <Pre label="Raw request">{request}</Pre>}
          {response && <Pre label="Raw response">{response}</Pre>}
        </CardContent>
      )}
    </Card>
  );
}

function Meta({ label, children, mono }: { label: string; children: React.ReactNode; mono?: boolean }) {
  return (
    <div>
      <dt className="text-xs uppercase tracking-wide text-muted-foreground">{label}</dt>
      <dd className={cn("break-all", mono && "font-mono text-xs")}>{children}</dd>
    </div>
  );
}

function Pre({ label, children }: { label: string; children: string }) {
  return (
    <div>
      <div className="mb-1 text-xs uppercase tracking-wide text-muted-foreground">{label}</div>
      <pre className="max-h-64 overflow-auto rounded-md border border-border bg-background p-3 font-mono text-xs leading-relaxed">
        {children}
      </pre>
    </div>
  );
}
