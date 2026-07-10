"use client";

import { useEffect, useState } from "react";
import {
  Activity, TrendingUp, TrendingDown, Minus, Server, Link2, Network, ShieldAlert,
  KeyRound, GitBranch, ArrowUpRight, ArrowDownRight,
} from "lucide-react";
import { api, type AttackSurface, type SurfaceSeriesPoint } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { severityClasses } from "@/lib/severity";
import { timeAgo } from "@/lib/utils";

const CATS = [
  { key: "assets", label: "Assets", Icon: Server },
  { key: "endpoints", label: "Endpoints", Icon: Link2 },
  { key: "ports", label: "Open ports", Icon: Network },
  { key: "findings", label: "Findings", Icon: ShieldAlert },
  { key: "secrets", label: "Secrets", Icon: KeyRound },
  { key: "leaks", label: "Leaks", Icon: GitBranch },
] as const;

/** Minimal responsive area+line chart of the total-surface series (no chart lib). */
function TrendChart({ series }: { series: SurfaceSeriesPoint[] }) {
  const W = 640;
  const H = 150;
  const pad = 10;
  const vals = series.map((s) => s.total);
  const max = Math.max(1, ...vals);
  const n = series.length;
  const x = (i: number) => (n <= 1 ? W / 2 : pad + (i * (W - 2 * pad)) / (n - 1));
  const y = (v: number) => H - pad - (v / max) * (H - 2 * pad);
  const line = series.map((s, i) => `${i === 0 ? "M" : "L"}${x(i)},${y(s.total)}`).join(" ");
  const area = `${line} L${x(n - 1)},${H - pad} L${x(0)},${H - pad} Z`;

  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="h-40 w-full text-primary" preserveAspectRatio="none">
      <defs>
        <linearGradient id="surfaceFill" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="currentColor" stopOpacity="0.22" />
          <stop offset="100%" stopColor="currentColor" stopOpacity="0" />
        </linearGradient>
      </defs>
      {n > 1 && <path d={area} fill="url(#surfaceFill)" stroke="none" />}
      <path
        d={n > 1 ? line : `M${pad},${y(vals[0] ?? 0)} L${W - pad},${y(vals[0] ?? 0)}`}
        fill="none"
        stroke="currentColor"
        strokeWidth={2}
        vectorEffect="non-scaling-stroke"
      />
      {series.map((s, i) => (
        <circle key={s.at} cx={x(i)} cy={y(s.total)} r={2.5} fill="currentColor" />
      ))}
    </svg>
  );
}

function ChangeBadge({ opened, resolved }: { opened: number; resolved: number }) {
  return (
    <span className="flex items-center gap-2 text-xs">
      {opened > 0 && (
        <span className="flex items-center gap-0.5 text-severity-high">
          <ArrowUpRight className="h-3.5 w-3.5" />
          {opened}
        </span>
      )}
      {resolved > 0 && (
        <span className="flex items-center gap-0.5 text-severity-low">
          <ArrowDownRight className="h-3.5 w-3.5" />
          {resolved}
        </span>
      )}
      {opened === 0 && resolved === 0 && <span className="text-muted-foreground">no change</span>}
    </span>
  );
}

export function AttackSurfaceView({ programId }: { programId: string }) {
  const [data, setData] = useState<AttackSurface | null>(null);
  const [err, setErr] = useState("");

  useEffect(() => {
    api.getAttackSurface(programId).then(setData).catch((e) => setErr(e.message));
  }, [programId]);

  if (err) return <p className="text-sm text-severity-critical">{err}</p>;
  if (!data) return <p className="text-sm text-muted-foreground">Loading…</p>;

  const net = data.change.net;
  const Trend = net > 0 ? TrendingUp : net < 0 ? TrendingDown : Minus;
  const trendColor =
    net > 0 ? "text-severity-high" : net < 0 ? "text-severity-low" : "text-muted-foreground";
  const trendWord = net > 0 ? "expanding" : net < 0 ? "shrinking" : "stable";

  return (
    <div className="space-y-4">
      {/* headline + trend chart */}
      <Card>
        <CardContent className="space-y-4 p-5">
          <div className="flex flex-wrap items-end justify-between gap-4">
            <div>
              <div className="flex items-center gap-2 text-sm text-muted-foreground">
                <Activity className="h-4 w-4 text-primary" /> Attack surface
              </div>
              <div className="mt-1 flex items-baseline gap-3">
                <span className="text-4xl font-semibold tracking-tight">{data.current.total}</span>
                <span className="text-sm text-muted-foreground">exposed items</span>
              </div>
            </div>
            <div className={`flex items-center gap-1.5 text-sm font-medium ${trendColor}`}>
              <Trend className="h-4 w-4" />
              {net > 0 ? `+${net}` : net}
              <span className="text-muted-foreground">since last scan · {trendWord}</span>
            </div>
          </div>

          {data.series.length > 0 ? (
            <TrendChart series={data.series} />
          ) : (
            <div className="flex h-40 items-center justify-center text-sm text-muted-foreground">
              Run a scan to start tracking how your surface changes.
            </div>
          )}
          <div className="flex justify-between text-xs text-muted-foreground">
            <span>{data.scan_count} scan{data.scan_count === 1 ? "" : "s"} recorded</span>
            <span>
              {data.latest_scan_at ? `last scan ${timeAgo(data.latest_scan_at)}` : "not scanned yet"}
            </span>
          </div>
        </CardContent>
      </Card>

      {/* composition + per-category change */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-3">
        {CATS.map(({ key, label, Icon }) => {
          const cur = data.current[key];
          const ch = data.change[key];
          return (
            <Card key={key}>
              <CardContent className="space-y-2 p-4">
                <div className="flex items-center gap-2 text-xs text-muted-foreground">
                  <Icon className="h-3.5 w-3.5" /> {label}
                </div>
                <div className="flex items-end justify-between">
                  <span className="text-2xl font-semibold">{cur.total}</span>
                  <ChangeBadge opened={ch.opened} resolved={ch.resolved} />
                </div>
                {key === "findings" && cur.total > 0 && (
                  <div className="flex flex-wrap gap-1.5 pt-1 text-[10px]">
                    {(["critical", "high", "medium", "low"] as const).map((s) =>
                      cur[s] ? (
                        <span key={s} className={`rounded border px-1 ${severityClasses[s]}`}>
                          {cur[s]} {s}
                        </span>
                      ) : null,
                    )}
                  </div>
                )}
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* change log */}
      <Card>
        <CardContent className="p-5">
          <div className="mb-3 flex items-center gap-2 text-sm font-semibold">
            <Activity className="h-4 w-4 text-primary" /> Recent changes
          </div>
          {data.recent.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No changes since the previous scan — surface is steady.
            </p>
          ) : (
            <div className="space-y-1.5">
              {data.recent.map((e, i) => {
                const opened = e.kind === "opened";
                return (
                  <div key={i} className="flex items-center gap-3 text-sm">
                    <span
                      className={`flex items-center gap-1 text-xs font-medium ${
                        opened ? "text-severity-high" : "text-severity-low"
                      }`}
                    >
                      {opened ? (
                        <ArrowUpRight className="h-3.5 w-3.5" />
                      ) : (
                        <ArrowDownRight className="h-3.5 w-3.5" />
                      )}
                      {opened ? "opened" : "closed"}
                    </span>
                    <span className="rounded bg-muted px-1.5 py-0.5 text-[10px] capitalize text-muted-foreground">
                      {e.type}
                    </span>
                    <span className="min-w-0 flex-1 truncate font-mono text-xs">{e.label}</span>
                    <span className="shrink-0 text-xs text-muted-foreground">{timeAgo(e.at)}</span>
                  </div>
                );
              })}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
