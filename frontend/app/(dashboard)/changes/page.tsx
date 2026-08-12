"use client";

import { useEffect, useMemo, useState } from "react";
import {
  GitCompareArrows, TrendingUp, TrendingDown, Minus, Plus, ArrowRight, Pencil,
  Server, Link2, Network, ShieldAlert, KeyRound, GitBranch,
} from "lucide-react";
import { api, type AttackSurface, type Delta, type SurfaceSeriesPoint } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { cn, timeAgo } from "@/lib/utils";

interface Bundle {
  pid: string;
  apex: string;
  surface: AttackSurface;
  deltas: Delta[];
  gone: Evt[]; // items no longer live (assets/endpoints/ports) since the last sweep
}

const TYPE_ICON: Record<string, React.ComponentType<{ className?: string }>> = {
  asset: Server,
  endpoint: Link2,
  port: Network,
  finding: ShieldAlert,
  secret: KeyRound,
  leak: GitBranch,
};
// deltas that are genuine in-place modifications (vs additions)
const MODIFIED_KINDS = new Set(["status_change", "title_change", "tech_change", "cert_change"]);
const KIND_LABEL: Record<string, string> = {
  status_change: "HTTP status",
  title_change: "Page title",
  tech_change: "Technology",
  cert_change: "TLS cert",
};

interface Evt {
  type: string;
  label: string;
  at: string;
  apex?: string;
  severity?: string | null;
}
interface Mod {
  kind: string;
  before?: string | null;
  after?: string | null;
  at: string;
  apex?: string;
}

/** Minimal area+line trend of total surface over scans. */
function TrendChart({ series }: { series: SurfaceSeriesPoint[] }) {
  const W = 680;
  const H = 130;
  const pad = 8;
  const vals = series.map((s) => s.total);
  const max = Math.max(1, ...vals);
  const n = series.length;
  const x = (i: number) => (n <= 1 ? W / 2 : pad + (i * (W - 2 * pad)) / (n - 1));
  const y = (v: number) => H - pad - (v / max) * (H - 2 * pad);
  const line = series.map((s, i) => `${i === 0 ? "M" : "L"}${x(i)},${y(s.total)}`).join(" ");
  const area = `${line} L${x(n - 1)},${H - pad} L${x(0)},${H - pad} Z`;
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="h-32 w-full text-primary" preserveAspectRatio="none">
      <defs>
        <linearGradient id="chg" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="currentColor" stopOpacity="0.2" />
          <stop offset="100%" stopColor="currentColor" stopOpacity="0" />
        </linearGradient>
      </defs>
      {n > 1 && <path d={area} fill="url(#chg)" stroke="none" />}
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

export default function ChangesPage() {
  const [bundles, setBundles] = useState<Bundle[]>([]);
  const [programs, setPrograms] = useState<[string, string][]>([]);
  const [program, setProgram] = useState("all");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    (async () => {
      try {
        const ps = await api.listPrograms();
        setPrograms(ps.map((p) => [p.program_id, p.apex_domain]));
        const bs = await Promise.all(
          ps.map(async (p) => {
            const [surface, deltas, assets, endpoints, ports] = await Promise.all([
              api.getAttackSurface(p.program_id).catch(() => null),
              api.listDeltas(p.program_id).catch(() => [] as Delta[]),
              api.listAssets(p.program_id).catch(() => []),
              api.listEndpoints(p.program_id).catch(() => []),
              api.listPorts(p.program_id).catch(() => []),
            ]);
            if (!surface) return null;
            const gone: Evt[] = [
              ...assets.filter((a) => a.gone).map((a) => ({ type: "asset", label: a.hostname, at: a.last_seen || "", apex: p.apex_domain })),
              ...endpoints.filter((e) => e.gone).map((e) => ({ type: "endpoint", label: e.url, at: e.last_seen || "", apex: p.apex_domain })),
              ...ports.filter((pt) => pt.gone).map((pt) => ({ type: "port", label: `${pt.ip}:${pt.port}`, at: pt.last_seen || "", apex: p.apex_domain })),
            ];
            return { pid: p.program_id, apex: p.apex_domain, surface, deltas, gone };
          }),
        );
        setBundles(bs.filter((b): b is Bundle => b !== null));
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  const scoped = useMemo(
    () => (program === "all" ? bundles : bundles.filter((b) => b.pid === program)),
    [bundles, program],
  );

  const { added, removed, modified, addN, remN, modN, single } = useMemo(() => {
    const added: Evt[] = [];
    const removed: Evt[] = [];
    const modified: Mod[] = [];
    const seen = new Set<string>();
    for (const b of scoped) {
      for (const e of b.surface.recent) {
        const evt: Evt = { type: e.type, label: e.label, at: e.at, apex: b.apex, severity: e.severity };
        if (e.kind === "opened") added.push(evt);
        else {
          removed.push(evt);
          seen.add(`${evt.type}:${evt.label}`);
        }
      }
      // items the readers flag as gone (no longer live) — dedupe against surface events
      for (const g of b.gone)
        if (!seen.has(`${g.type}:${g.label}`)) {
          seen.add(`${g.type}:${g.label}`);
          removed.push(g);
        }
      for (const d of b.deltas)
        if (MODIFIED_KINDS.has(d.kind))
          modified.push({ kind: d.kind, before: d.before, after: d.after, at: d.observed_at || "", apex: b.apex });
    }
    added.sort((a, z) => z.at.localeCompare(a.at));
    removed.sort((a, z) => z.at.localeCompare(a.at));
    modified.sort((a, z) => z.at.localeCompare(a.at));
    return {
      added,
      removed,
      modified,
      addN: added.length,
      remN: removed.length,
      modN: modified.length,
      single: scoped.length === 1 ? scoped[0] : null,
    };
  }, [scoped]);

  const net = addN - remN;
  const Trend = net > 0 ? TrendingUp : net < 0 ? TrendingDown : Minus;
  const trendColor =
    net > 0 ? "text-severity-high" : net < 0 ? "text-severity-low" : "text-muted-foreground";

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-semibold tracking-tight">
            <GitCompareArrows className="h-6 w-6 text-primary" /> Changes
          </h1>
          <p className="text-sm text-muted-foreground">
            What&apos;s new, gone, and changed on your attack surface since the last scan.
          </p>
        </div>
        <select
          value={program}
          onChange={(e) => setProgram(e.target.value)}
          className="h-9 rounded-md border border-border bg-background px-3 text-sm"
        >
          <option value="all">All programs</option>
          {programs.map(([id, apex]) => (
            <option key={id} value={id}>
              {apex}
            </option>
          ))}
        </select>
      </div>

      {/* diff stat banner (git-style +/−/~) */}
      <Card>
        <CardContent className="flex flex-wrap items-center gap-x-8 gap-y-3 p-5">
          <DiffStat icon={Plus} label="New" value={addN} cls="text-severity-high" />
          <DiffStat icon={Minus} label="Gone" value={remN} cls="text-severity-low" />
          <DiffStat icon={Pencil} label="Modified" value={modN} cls="text-primary" />
          <div className={cn("ml-auto flex items-center gap-1.5 text-sm font-medium", trendColor)}>
            <Trend className="h-4 w-4" />
            {net > 0 ? `+${net}` : net} net · {net > 0 ? "expanding" : net < 0 ? "shrinking" : "stable"}
          </div>
        </CardContent>
      </Card>

      {/* trend chart (single program) */}
      {single && single.surface.series.length > 1 && (
        <Card>
          <CardContent className="space-y-2 p-5">
            <div className="flex items-baseline justify-between">
              <span className="text-sm font-semibold">Surface over time</span>
              <span className="text-xs text-muted-foreground">
                {single.surface.scan_count} scans · now {single.surface.current.total} items
              </span>
            </div>
            <TrendChart series={single.surface.series} />
          </CardContent>
        </Card>
      )}

      {loading ? (
        <p className="py-8 text-center text-sm text-muted-foreground">Loading…</p>
      ) : (
        <div className="grid gap-4 lg:grid-cols-2">
          <DiffBlock
            title="New — added to your surface"
            marker="+"
            accent="text-severity-high"
            border="border-l-severity-high"
            events={added}
            showApex={program === "all"}
            empty="Nothing new since the last scan."
          />
          <DiffBlock
            title="Gone — removed or fixed"
            marker="−"
            accent="text-severity-low"
            border="border-l-severity-low"
            events={removed}
            showApex={program === "all"}
            empty="Nothing dropped off since the last scan."
          />
          <div className="lg:col-span-2">
            <ModifiedBlock mods={modified} showApex={program === "all"} />
          </div>
        </div>
      )}
    </div>
  );
}

function DiffStat({
  icon: Icon,
  label,
  value,
  cls,
}: {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  value: number;
  cls: string;
}) {
  return (
    <div className="flex items-center gap-2">
      <Icon className={cn("h-5 w-5", cls)} />
      <span className={cn("text-2xl font-semibold", cls)}>{value}</span>
      <span className="text-sm text-muted-foreground">{label}</span>
    </div>
  );
}

function DiffBlock({
  title,
  marker,
  accent,
  border,
  events,
  showApex,
  empty,
}: {
  title: string;
  marker: string;
  accent: string;
  border: string;
  events: Evt[];
  showApex: boolean;
  empty: string;
}) {
  // group by type for readability
  const groups = useMemo(() => {
    const m = new Map<string, Evt[]>();
    events.forEach((e) => m.set(e.type, [...(m.get(e.type) || []), e]));
    return [...m.entries()];
  }, [events]);

  return (
    <Card className="min-w-0">
      <CardContent className="min-w-0 p-4 sm:p-5">
        <div className="mb-3 text-sm font-semibold">{title}</div>
        {events.length === 0 ? (
          <p className="text-sm text-muted-foreground">{empty}</p>
        ) : (
          <div className="space-y-3">
            {groups.map(([type, items]) => {
              const Icon = TYPE_ICON[type] || Link2;
              return (
                <div key={type}>
                  <div className="mb-1 flex items-center gap-1.5 text-xs uppercase tracking-wide text-muted-foreground">
                    <Icon className="h-3.5 w-3.5" /> {type}s
                    <span className="opacity-60">{items.length}</span>
                  </div>
                  <div className="space-y-0.5">
                    {items.slice(0, 40).map((e, i) => (
                      <div
                        key={i}
                        className={cn(
                          "flex min-w-0 items-center gap-2 border-l-2 pl-2 font-mono text-xs",
                          border,
                        )}
                      >
                        <span className={cn("font-bold", accent)}>{marker}</span>
                        <span className="min-w-0 flex-1 break-all sm:truncate">{e.label}</span>
                        {showApex && (
                          <span className="hidden shrink-0 text-[10px] text-muted-foreground sm:inline">{e.apex}</span>
                        )}
                        <span className="hidden shrink-0 text-[10px] text-muted-foreground sm:inline">
                          {timeAgo(e.at)}
                        </span>
                      </div>
                    ))}
                    {items.length > 40 && (
                      <div className="pl-4 text-[10px] text-muted-foreground">
                        +{items.length - 40} more
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function ModifiedBlock({ mods, showApex }: { mods: Mod[]; showApex: boolean }) {
  return (
    <Card className="min-w-0">
      <CardContent className="min-w-0 p-4 sm:p-5">
        <div className="mb-3 flex items-center gap-2 text-sm font-semibold">
          <Pencil className="h-4 w-4 text-primary" /> Modified — changed in place
        </div>
        {mods.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            No in-place changes (status / title / tech / cert) since the last scan.
          </p>
        ) : (
          <div className="space-y-1">
            {mods.slice(0, 60).map((m, i) => (
              <div key={i} className="flex min-w-0 items-center gap-2 text-xs">
                <span className="w-24 shrink-0 rounded bg-muted px-1.5 py-0.5 text-center text-[10px] text-muted-foreground">
                  {KIND_LABEL[m.kind] || m.kind}
                </span>
                <span className="min-w-0 flex-1 break-all font-mono sm:truncate">
                  <span className="text-muted-foreground line-through">{m.before || "—"}</span>
                  <ArrowRight className="mx-1 inline h-3 w-3 text-muted-foreground" />
                  <span className="text-foreground">{m.after || "—"}</span>
                </span>
                {showApex && (
                  <span className="hidden shrink-0 text-[10px] text-muted-foreground sm:inline">{m.apex}</span>
                )}
                <span className="hidden shrink-0 text-[10px] text-muted-foreground sm:inline">{timeAgo(m.at)}</span>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
