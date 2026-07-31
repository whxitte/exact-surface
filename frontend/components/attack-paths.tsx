"use client";

import { useEffect, useState } from "react";
import { Route, ChevronRight } from "lucide-react";
import { api, type AttackPath } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";

const SEV: Record<string, string> = {
  critical: "text-severity-critical",
  high: "text-severity-high",
  medium: "text-severity-medium",
  low: "text-severity-low",
  info: "text-muted-foreground",
};

/**
 * Attack paths — the findings on one host, told in the order an attacker would use them.
 *
 * This is the narrative layer, and it is deliberately conservative: a host needs
 * findings spanning two or more attacker phases before anything is called a path.
 * Turning a single finding into a "chain" would make the feature worthless and the
 * product less trustworthy, so the empty state says so plainly rather than padding.
 *
 * Every step names the check it came from, because a story nobody can verify is
 * marketing rather than evidence.
 */
export function AttackPaths({ programId }: { programId: string }) {
  const [paths, setPaths] = useState<AttackPath[]>([]);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    api
      .getAttackPaths(programId)
      .then((r) => setPaths(r.paths))
      .catch(() => setPaths([]))
      .finally(() => setLoaded(true));
  }, [programId]);

  if (!loaded) return null;

  return (
    <Card>
      <CardContent className="p-5">
        <div className="flex items-center gap-2">
          <Route className="h-4 w-4 text-primary" />
          <h2 className="text-sm font-semibold">Attack paths</h2>
          {paths.length > 0 && (
            <span className="rounded bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground">
              {paths.length}
            </span>
          )}
        </div>

        {paths.length === 0 ? (
          <p className="mt-2 text-xs text-muted-foreground">
            No attack path yet. A path needs findings on the same host spanning at least two
            stages of an attack — an exposure that leads somewhere. Individual findings are
            listed under Findings; calling one of them a &ldquo;chain&rdquo; would overstate it.
          </p>
        ) : (
          <div className="mt-3 space-y-3">
            <p className="text-xs text-muted-foreground">
              Findings on one host, in the order an attacker would use them. Each step names the
              check it came from so you can verify the claim.
            </p>
            {paths.map((p) => (
              <div key={p.host} className="rounded-md border border-border p-3">
                <div className="flex flex-wrap items-baseline justify-between gap-2">
                  <span className="font-mono text-sm font-medium">{p.host}</span>
                  <span className={cn("text-[11px] uppercase", SEV[p.severity] ?? "")}>
                    {p.severity} · risk {p.risk_score}
                  </span>
                </div>
                <p className="mt-1.5 text-xs text-muted-foreground">{p.summary}</p>
                <ol className="mt-2.5 space-y-1.5">
                  {p.steps.map((s, i) => (
                    <li key={`${s.finding_id}-${i}`} className="flex items-start gap-2 text-xs">
                      <span className="mt-0.5 font-mono text-[10px] uppercase text-muted-foreground">
                        {s.phase}
                      </span>
                      <ChevronRight className="mt-0.5 h-3 w-3 shrink-0 text-muted-foreground" />
                      <span className="min-w-0 flex-1">
                        {s.text}
                        <span className="ml-1.5 font-mono text-[10px] text-muted-foreground">
                          ({s.check_id})
                        </span>
                      </span>
                      <span className={cn("shrink-0 text-[10px]", SEV[s.severity] ?? "")}>
                        {s.severity}
                      </span>
                    </li>
                  ))}
                </ol>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
