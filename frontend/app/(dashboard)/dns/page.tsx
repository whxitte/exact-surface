"use client";

import { useEffect, useMemo, useState } from "react";
import { Network, Search, Cloud, Server, Mail } from "lucide-react";
import { api, type Asset } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";

interface Row {
  asset: Asset;
  program_id: string;
  apex: string;
}

const TYPES = ["a", "aaaa", "cname", "ns", "mx", "txt"] as const;
const LABEL: Record<string, string> = {
  a: "A",
  aaaa: "AAAA",
  cname: "CNAME",
  ns: "NS",
  mx: "MX",
  txt: "TXT",
};

export default function DnsPage() {
  const [rows, setRows] = useState<Row[]>([]);
  const [loading, setLoading] = useState(true);
  const [program, setProgram] = useState("all");
  const [type, setType] = useState<string>("all");
  const [q, setQ] = useState("");
  const [programs, setPrograms] = useState<[string, string][]>([]);

  useEffect(() => {
    (async () => {
      try {
        const ps = await api.listPrograms();
        setPrograms(ps.map((p) => [p.program_id, p.apex_domain]));
        const all: Row[] = [];
        for (const p of ps) {
          const assets = await api.listAssets(p.program_id);
          assets.forEach((a) => {
            if (a.dns_records && Object.keys(a.dns_records).length)
              all.push({ asset: a, program_id: p.program_id, apex: p.apex_domain });
          });
        }
        all.sort((x, y) => x.asset.hostname.localeCompare(y.asset.hostname));
        setRows(all);
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  const scoped = useMemo(
    () => (program === "all" ? rows : rows.filter((r) => r.program_id === program)),
    [rows, program],
  );

  const shown = useMemo(
    () =>
      scoped.filter(
        (r) =>
          (type === "all" || r.asset.dns_records?.[type]?.length) &&
          (!q || r.asset.hostname.toLowerCase().includes(q.toLowerCase())),
      ),
    [scoped, type, q],
  );

  const withCname = scoped.filter((r) => r.asset.dns_records?.cname?.length).length;
  const nameservers = new Set(scoped.flatMap((r) => r.asset.dns_records?.ns || [])).size;
  const mail = new Set(scoped.flatMap((r) => r.asset.dns_records?.mx || [])).size;

  // Group hosts by CNAME target — reveals the cloud services behind the domain.
  const cnameGroups = useMemo(() => {
    const m = new Map<string, string[]>();
    scoped.forEach((r) =>
      (r.asset.dns_records?.cname || []).forEach((c) => {
        const list = m.get(c) || [];
        list.push(r.asset.hostname);
        m.set(c, list);
      }),
    );
    return [...m.entries()].sort((a, b) => b[1].length - a[1].length);
  }, [scoped]);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">DNS</h1>
        <p className="text-sm text-muted-foreground">
          The full DNS map of your surface — where records point, and which cloud services sit
          behind each host.
        </p>
      </div>

      {/* summary */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatTile icon={Network} label="Hosts with records" value={scoped.length} />
        <StatTile icon={Cloud} label="Hosts with CNAME" value={withCname} accent />
        <StatTile icon={Server} label="Unique nameservers" value={nameservers} />
        <StatTile icon={Mail} label="Mail endpoints (MX)" value={mail} />
      </div>

      {/* controls */}
      <div className="flex flex-wrap items-center gap-2">
        {["all", ...TYPES].map((t) => (
          <button
            key={t}
            onClick={() => setType(t)}
            className={cn(
              "rounded-full border px-3 py-1 text-xs uppercase transition-colors",
              type === t
                ? "border-primary bg-primary/10 text-primary"
                : "border-border text-muted-foreground hover:text-foreground",
            )}
          >
            {t === "all" ? "All" : LABEL[t]}
          </button>
        ))}
        <div className="relative ml-auto">
          <Search className="pointer-events-none absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search host…"
            className="h-8 w-48 rounded-md border border-border bg-background pl-7 pr-2 text-xs"
          />
        </div>
        <select
          value={program}
          onChange={(e) => setProgram(e.target.value)}
          className="h-8 rounded-md border border-border bg-background px-2 text-xs"
        >
          <option value="all">All programs</option>
          {programs.map(([id, apex]) => (
            <option key={id} value={id}>
              {apex}
            </option>
          ))}
        </select>
      </div>

      {/* CNAME spotlight */}
      {cnameGroups.length > 0 && (
        <Card>
          <CardContent className="space-y-3 p-5">
            <div className="flex items-center gap-2 text-sm font-semibold">
              <Cloud className="h-4 w-4 text-severity-medium" /> CNAME targets
              <span className="text-xs font-normal text-muted-foreground">
                — the services your hosts delegate to
              </span>
            </div>
            <div className="space-y-1.5">
              {cnameGroups.slice(0, 12).map(([target, hosts]) => (
                <div key={target} className="flex items-center gap-3 text-sm">
                  <span className="w-8 shrink-0 text-right font-mono text-xs text-muted-foreground">
                    {hosts.length}
                  </span>
                  <span className="shrink-0 font-mono text-xs text-severity-medium">{target}</span>
                  <span className="min-w-0 flex-1 truncate text-xs text-muted-foreground">
                    {hosts.slice(0, 4).join(", ")}
                    {hosts.length > 4 ? ` +${hosts.length - 4}` : ""}
                  </span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* per-host records */}
      {loading ? (
        <p className="py-8 text-center text-sm text-muted-foreground">Loading…</p>
      ) : shown.length === 0 ? (
        <p className="py-8 text-center text-sm text-muted-foreground">
          No DNS records yet — run a scan to enumerate them.
        </p>
      ) : (
        <div className="space-y-2">
          {shown.map((r) => (
            <Card key={r.asset.fingerprint}>
              <CardContent className="space-y-2 p-4">
                <div className="flex items-center gap-2">
                  <span className="font-medium">{r.asset.hostname}</span>
                  {program === "all" && (
                    <span className="text-xs text-muted-foreground">· {r.apex}</span>
                  )}
                </div>
                <div className="grid gap-1.5 sm:grid-cols-2">
                  {TYPES.filter((t) => r.asset.dns_records?.[t]?.length).map((t) => (
                    <div key={t} className="flex gap-2 text-xs">
                      <span
                        className={cn(
                          "w-12 shrink-0 rounded px-1 text-center font-mono",
                          t === "cname"
                            ? "bg-severity-medium/15 text-severity-medium"
                            : "bg-muted text-muted-foreground",
                        )}
                      >
                        {LABEL[t]}
                      </span>
                      <span className="min-w-0 break-all font-mono text-muted-foreground">
                        {r.asset.dns_records![t].join(", ")}
                      </span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

function StatTile({
  icon: Icon,
  label,
  value,
  accent,
}: {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  value: number;
  accent?: boolean;
}) {
  return (
    <Card>
      <CardContent className="p-4">
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          <Icon className={cn("h-3.5 w-3.5", accent ? "text-severity-medium" : "text-primary")} />
          {label}
        </div>
        <div className="mt-1 text-2xl font-semibold">{value}</div>
      </CardContent>
    </Card>
  );
}
