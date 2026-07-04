"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { api, type Finding } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { SeverityBadge } from "@/components/ui/badge";
import { SEVERITIES, severityRank } from "@/lib/severity";
import { cn } from "@/lib/utils";

interface Row extends Finding {
  program_id: string;
  apex: string;
}

export default function FindingsPage() {
  const [rows, setRows] = useState<Row[]>([]);
  const [filter, setFilter] = useState<string>("all");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    (async () => {
      try {
        const programs = await api.listPrograms();
        const all: Row[] = [];
        for (const p of programs) {
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
    () => (filter === "all" ? rows : rows.filter((r) => r.severity === filter)),
    [rows, filter],
  );

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Findings</h1>
        <p className="text-sm text-muted-foreground">Everything an attacker could act on, ranked.</p>
      </div>

      <div className="flex gap-2">
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
      </div>

      {loading ? (
        <p className="py-8 text-center text-sm text-muted-foreground">Loading…</p>
      ) : shown.length === 0 ? (
        <p className="py-8 text-center text-sm text-muted-foreground">No findings match.</p>
      ) : (
        <div className="space-y-2">
          {shown.map((f) => (
            <Link key={`${f.program_id}-${f.fingerprint}`} href={`/programs/${f.program_id}`}>
              <Card className="transition-colors hover:border-primary/40">
                <CardContent className="flex items-center gap-4 p-4">
                  <SeverityBadge severity={f.severity} />
                  <div className="min-w-0 flex-1">
                    <div className="truncate font-medium">{f.name}</div>
                    <div className="truncate font-mono text-xs text-muted-foreground">
                      {f.location}
                    </div>
                  </div>
                  {f.is_new && <span className="text-xs text-primary">NEW</span>}
                  <span className="hidden text-xs text-muted-foreground md:inline">{f.apex}</span>
                </CardContent>
              </Card>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}
