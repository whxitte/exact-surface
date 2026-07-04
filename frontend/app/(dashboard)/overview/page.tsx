"use client";

import { useEffect, useState } from "react";
import { Globe, Server, KeyRound, ShieldAlert, Sparkles } from "lucide-react";
import { api, type Stats } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { SEVERITIES } from "@/lib/severity";
import { severityDot } from "@/lib/severity";

function Stat({ icon: Icon, label, value, accent }: {
  icon: React.ElementType; label: string; value: number | string; accent?: boolean;
}) {
  return (
    <Card>
      <CardContent className="flex items-center gap-4 p-5">
        <div className={`flex h-10 w-10 items-center justify-center rounded-md ${accent ? "bg-primary/15 text-primary" : "bg-muted text-muted-foreground"}`}>
          <Icon className="h-5 w-5" />
        </div>
        <div>
          <div className="text-2xl font-semibold tabular-nums">{value}</div>
          <div className="text-xs uppercase tracking-wide text-muted-foreground">{label}</div>
        </div>
      </CardContent>
    </Card>
  );
}

export default function OverviewPage() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    api.stats().then(setStats).catch((e) => setError(e.message));
  }, []);

  const bySev = stats?.findings_by_severity ?? {};
  const maxSev = Math.max(1, ...Object.values(bySev));

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Overview</h1>
        <p className="text-sm text-muted-foreground">What an attacker sees, right now.</p>
      </div>

      {error && <p className="text-sm text-severity-critical">{error}</p>}

      <div className="grid grid-cols-2 gap-4 md:grid-cols-5">
        <Stat icon={Globe} label="Programs" value={stats?.programs ?? "—"} />
        <Stat icon={Server} label="Assets" value={stats?.assets ?? "—"} />
        <Stat icon={ShieldAlert} label="Findings" value={stats?.findings ?? "—"} />
        <Stat icon={KeyRound} label="Secrets" value={stats?.secrets ?? "—"} />
        <Stat icon={Sparkles} label="New" value={stats?.new_findings ?? "—"} accent />
      </div>

      <Card>
        <CardContent className="p-5">
          <h2 className="mb-4 text-sm font-semibold">Findings by severity</h2>
          <div className="space-y-3">
            {SEVERITIES.map((sev) => {
              const count = bySev[sev] ?? 0;
              return (
                <div key={sev} className="flex items-center gap-3">
                  <div className="flex w-20 items-center gap-2 text-xs capitalize text-muted-foreground">
                    <span className={`h-2 w-2 rounded-full ${severityDot[sev]}`} />
                    {sev}
                  </div>
                  <div className="h-2 flex-1 overflow-hidden rounded-full bg-muted">
                    <div
                      className={severityDot[sev]}
                      style={{ width: `${(count / maxSev) * 100}%`, height: "100%" }}
                    />
                  </div>
                  <div className="w-8 text-right text-sm tabular-nums">{count}</div>
                </div>
              );
            })}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
