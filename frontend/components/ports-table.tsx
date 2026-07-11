"use client";

import { useMemo, useState } from "react";
import { EyeOff } from "lucide-react";
import { type Port } from "@/lib/api";
import { SeverityBadge } from "@/components/ui/badge";
import { portReason, portSeverity } from "@/lib/ports";
import { severityRank } from "@/lib/severity";
import { timeAgo } from "@/lib/utils";
import { cn } from "@/lib/utils";

const SEVS = ["all", "critical", "high", "medium", "info"] as const;

export function PortsTable({
  ports,
  hostsByIp,
}: {
  ports: Port[];
  hostsByIp: Map<string, string[]>;
}) {
  const [sev, setSev] = useState<string>("all");
  const [showGone, setShowGone] = useState(false);

  const rows = useMemo(
    () =>
      ports
        .map((p) => ({
          p,
          severity: portSeverity(p.port),
          reason: portReason(p.port, p.service),
          host: (hostsByIp.get(p.ip) || [])[0] || "",
          hostCount: (hostsByIp.get(p.ip) || []).length,
        }))
        .sort((a, b) => severityRank(a.severity) - severityRank(b.severity)),
    [ports, hostsByIp],
  );

  const goneCount = rows.filter((r) => r.p.gone).length;
  const live = rows.filter((r) => showGone || !r.p.gone);
  const shown = live.filter((r) => sev === "all" || r.severity === sev);

  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const r of live) c[r.severity] = (c[r.severity] || 0) + 1;
    return c;
  }, [live]);

  const topService = useMemo(() => {
    const c: Record<string, number> = {};
    for (const r of live) if (r.p.service) c[r.p.service] = (c[r.p.service] || 0) + 1;
    return Object.entries(c).sort((a, b) => b[1] - a[1])[0]?.[0] || "—";
  }, [live]);

  if (ports.length === 0) {
    return (
      <p className="py-8 text-center text-sm text-muted-foreground">
        No open ports — port scanning runs on confirmed-dedicated infra only (§9b).
      </p>
    );
  }

  return (
    <div className="space-y-4">
      {/* summary */}
      <div className="flex flex-wrap items-center gap-x-6 gap-y-1 text-sm">
        <span>
          Total: <span className="font-semibold">{live.length}</span>
        </span>
        <span>
          Critical: <span className="font-semibold text-severity-critical">{counts.critical || 0}</span>
        </span>
        <span>
          High: <span className="font-semibold text-severity-high">{counts.high || 0}</span>
        </span>
        <span className="text-muted-foreground">
          Top service: <span className="font-medium text-foreground">{topService}</span>
        </span>
      </div>

      {/* filters */}
      <div className="flex flex-wrap items-center gap-2">
        {SEVS.map((s) => (
          <button
            key={s}
            onClick={() => setSev(s)}
            className={cn(
              "rounded-full border px-3 py-1 text-xs capitalize transition-colors",
              sev === s
                ? "border-primary bg-primary/10 text-primary"
                : "border-border text-muted-foreground hover:text-foreground",
            )}
          >
            {s}
            {s !== "all" && counts[s] ? <span className="ml-1.5 opacity-60">{counts[s]}</span> : null}
          </button>
        ))}
        {goneCount > 0 && (
          <button
            onClick={() => setShowGone((v) => !v)}
            className={cn(
              "ml-auto flex items-center gap-1.5 rounded-md border px-2 py-1 text-xs transition-colors",
              showGone ? "border-primary/40 text-primary" : "border-border text-muted-foreground hover:text-foreground",
            )}
          >
            <EyeOff className="h-3.5 w-3.5" />
            {showGone ? "Hide" : "Show"} closed ({goneCount})
          </button>
        )}
      </div>

      {/* table */}
      <div className="overflow-x-auto rounded-lg border border-border">
        <table className="w-full text-left text-sm">
          <thead className="border-b border-border text-[11px] uppercase tracking-wide text-muted-foreground">
            <tr>
              <th className="px-4 py-2.5 font-medium">IP</th>
              <th className="px-4 py-2.5 font-medium">Port</th>
              <th className="px-4 py-2.5 font-medium">Service</th>
              <th className="px-4 py-2.5 font-medium">Product</th>
              <th className="px-4 py-2.5 font-medium">Severity</th>
              <th className="px-4 py-2.5 font-medium">Reason</th>
              <th className="px-4 py-2.5 font-medium">Domain</th>
              <th className="px-4 py-2.5 text-right font-medium">First seen</th>
            </tr>
          </thead>
          <tbody>
            {shown.map(({ p, severity, reason, host, hostCount }) => (
              <tr
                key={p.fingerprint}
                className={cn(
                  "border-b border-border/50 last:border-0 hover:bg-muted/30",
                  p.gone && "opacity-50",
                )}
              >
                <td className="whitespace-nowrap px-4 py-2.5 font-mono text-xs">{p.ip}</td>
                <td className="whitespace-nowrap px-4 py-2.5 font-mono text-xs text-primary">
                  {p.port}/{p.protocol}
                </td>
                <td className="px-4 py-2.5">{p.service || "—"}</td>
                <td className="px-4 py-2.5 text-muted-foreground">
                  {p.product ? `${p.product}${p.version ? ` ${p.version}` : ""}` : "—"}
                </td>
                <td className="px-4 py-2.5">
                  <SeverityBadge severity={severity} />
                </td>
                <td className="px-4 py-2.5 text-xs text-muted-foreground">{reason}</td>
                <td className="max-w-[220px] truncate px-4 py-2.5 font-mono text-xs">
                  {p.gone && <span className="mr-1 text-severity-medium">closed ·</span>}
                  {host || "—"}
                  {hostCount > 1 && <span className="text-muted-foreground"> +{hostCount - 1}</span>}
                </td>
                <td className="whitespace-nowrap px-4 py-2.5 text-right text-xs text-muted-foreground">
                  {timeAgo(p.first_seen)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
