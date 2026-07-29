"use client";

import { useMemo, useState } from "react";
import { FileCode2, Search, ExternalLink, Braces, AlertTriangle } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Select } from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import type { JsFile, JsItem } from "@/lib/api";

/**
 * JS Mine — what the app's own JavaScript gives away.
 *
 * Reading minified bundles by hand is the most tedious part of a real assessment, so
 * this presents the result the way a hunter would want it: one flat, filterable,
 * sortable list of everything extracted, always traceable back to the exact file it
 * came from.
 */

/** Tag → how it should read. Semantic colour, kept separate from the accent. */
const TAG_STYLE: Record<string, string> = {
  admin: "bg-severity-critical/15 text-severity-critical",
  credentials: "bg-severity-critical/15 text-severity-critical",
  exposure: "bg-severity-critical/15 text-severity-critical",
  internal: "bg-severity-high/15 text-severity-high",
  "non-production": "bg-severity-high/15 text-severity-high",
  auth: "bg-severity-medium/15 text-severity-medium",
  payment: "bg-severity-medium/15 text-severity-medium",
  "file-handling": "bg-severity-medium/15 text-severity-medium",
  graphql: "bg-severity-low/15 text-severity-low",
  "api-docs": "bg-severity-low/15 text-severity-low",
  api: "bg-primary/10 text-primary",
  "user-data": "bg-primary/10 text-primary",
  "own-domain": "bg-primary/10 text-primary",
};

type Row = JsItem & { file: string; fileName: string };

export function JsMineView({ files }: { files: JsFile[] }) {
  const [query, setQuery] = useState("");
  const [tag, setTag] = useState("all");
  const [kind, setKind] = useState("all");
  const [sort, setSort] = useState<"interest" | "path" | "file">("interest");
  const [openFile, setOpenFile] = useState<string>("all");

  // Flatten every bundle's items into one list — the view a hunter actually wants.
  const rows: Row[] = useMemo(() => {
    const out: Row[] = [];
    for (const f of files) {
      const fileName = f.url.split("/").pop() || f.url;
      for (const item of f.items || []) out.push({ ...item, file: f.url, fileName });
    }
    return out;
  }, [files]);

  const allTags = useMemo(() => {
    const set = new Set<string>();
    rows.forEach((r) => r.tags?.forEach((t) => set.add(t)));
    return Array.from(set).sort();
  }, [rows]);

  const shown = useMemo(() => {
    const q = query.trim().toLowerCase();
    const filtered = rows.filter((r) => {
      if (openFile !== "all" && r.file !== openFile) return false;
      if (kind !== "all" && r.kind !== kind) return false;
      if (tag === "interesting" && !(r.tags?.length > 0)) return false;
      if (tag !== "all" && tag !== "interesting" && !r.tags?.includes(tag)) return false;
      if (q && !r.value.toLowerCase().includes(q) && !r.fileName.toLowerCase().includes(q))
        return false;
      return true;
    });
    return filtered.sort((a, b) => {
      if (sort === "path") return a.value.localeCompare(b.value);
      if (sort === "file") return a.fileName.localeCompare(b.fileName) || a.value.localeCompare(b.value);
      // interest: most tags first, then alphabetical — the default a hunter wants
      return (b.tags?.length || 0) - (a.tags?.length || 0) || a.value.localeCompare(b.value);
    });
  }, [rows, query, tag, kind, sort, openFile]);

  const hostnames = useMemo(() => {
    const set = new Set<string>();
    files.forEach((f) => f.hostnames?.forEach((h) => set.add(h)));
    return Array.from(set).sort();
  }, [files]);

  const sourceMaps = files.filter((f) => f.source_map);
  const interesting = rows.filter((r) => r.tags?.length > 0).length;

  if (files.length === 0) {
    return (
      <p className="py-10 text-center text-sm text-muted-foreground">
        No JavaScript mined yet. Run a scan — the crawl finds the bundles, then JS Mine reads
        them for routes, hostnames and source maps.
      </p>
    );
  }

  return (
    <div className="space-y-4">
      {/* Summary */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Stat label="Bundles mined" value={files.length} icon={<FileCode2 className="h-4 w-4" />} />
        <Stat label="Paths & URLs" value={rows.length} icon={<Braces className="h-4 w-4" />} />
        <Stat label="Worth a look" value={interesting} accent icon={<AlertTriangle className="h-4 w-4" />} />
        <Stat label="Hostnames found" value={hostnames.length} icon={<ExternalLink className="h-4 w-4" />} />
      </div>

      {sourceMaps.length > 0 && (
        <Card className="border-severity-medium/40">
          <CardContent className="p-4 text-sm">
            <p className="font-medium text-severity-medium">
              {sourceMaps.length} source map{sourceMaps.length === 1 ? "" : "s"} published
            </p>
            <p className="mt-1 text-xs text-muted-foreground">
              A .map file lets anyone reconstruct your original, unminified source — comments,
              internal file names and all.
            </p>
            <ul className="mt-2 space-y-1">
              {sourceMaps.map((f) => (
                <li key={f.fingerprint}>
                  <a
                    href={f.source_map || "#"}
                    target="_blank"
                    rel="noreferrer"
                    className="font-mono text-xs text-primary hover:underline"
                  >
                    {f.source_map}
                  </a>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      )}

      {hostnames.length > 0 && (
        <Card>
          <CardContent className="p-4">
            <p className="text-sm font-medium">Hostnames referenced in JavaScript</p>
            <p className="mt-0.5 text-xs text-muted-foreground">
              Hosts the app talks to. Ones on your own domains that DNS enumeration missed are
              new attack surface.
            </p>
            <div className="mt-2 flex flex-wrap gap-1.5">
              {hostnames.map((h) => (
                <span key={h} className="rounded bg-muted px-2 py-0.5 font-mono text-[11px]">
                  {h}
                </span>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Controls */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative min-w-[200px] flex-1">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search paths, URLs or file names…"
            className="pl-8"
          />
        </div>
        <Select value={tag} onChange={(e) => setTag(e.target.value)} aria-label="Filter by tag">
          <option value="all">All items</option>
          <option value="interesting">Interesting only</option>
          {allTags.map((t) => (
            <option key={t} value={t}>{t}</option>
          ))}
        </Select>
        <Select value={kind} onChange={(e) => setKind(e.target.value)} aria-label="Filter by kind">
          <option value="all">Paths + URLs</option>
          <option value="path">Paths</option>
          <option value="url">URLs</option>
        </Select>
        <Select value={openFile} onChange={(e) => setOpenFile(e.target.value)} aria-label="Filter by file">
          <option value="all">All bundles</option>
          {files.map((f) => (
            <option key={f.fingerprint} value={f.url}>
              {f.url.split("/").pop()}
            </option>
          ))}
        </Select>
        <Select value={sort} onChange={(e) => setSort(e.target.value as typeof sort)} aria-label="Sort">
          <option value="interest">Sort: most interesting</option>
          <option value="path">Sort: path A–Z</option>
          <option value="file">Sort: by bundle</option>
        </Select>
      </div>

      <p className="text-xs text-muted-foreground">
        Showing {shown.length} of {rows.length} extracted items.
      </p>

      {/* Results */}
      <div className="space-y-1.5">
        {shown.slice(0, 500).map((r, i) => (
          <Card key={`${r.file}-${r.value}-${i}`}>
            <CardContent className="flex flex-wrap items-center gap-2 p-2.5">
              <span className="rounded bg-muted px-1.5 py-0.5 font-mono text-[10px] uppercase text-muted-foreground">
                {r.kind}
              </span>
              {r.absolute ? (
                <a
                  href={r.absolute}
                  target="_blank"
                  rel="noreferrer"
                  className="min-w-0 flex-1 truncate font-mono text-xs text-primary hover:underline"
                  title={r.absolute}
                >
                  {r.value}
                </a>
              ) : (
                <span className="min-w-0 flex-1 truncate font-mono text-xs">{r.value}</span>
              )}
              {r.tags?.map((t) => (
                <span
                  key={t}
                  className={`rounded px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide ${
                    TAG_STYLE[t] || "bg-muted text-muted-foreground"
                  }`}
                >
                  {t}
                </span>
              ))}
              <span
                className="hidden shrink-0 font-mono text-[10px] text-muted-foreground md:inline"
                title={`Found in ${r.file}`}
              >
                {r.fileName}
              </span>
            </CardContent>
          </Card>
        ))}
        {shown.length > 500 && (
          <p className="py-2 text-center text-xs text-muted-foreground">
            Showing the first 500 — narrow the filters to see the rest.
          </p>
        )}
        {shown.length === 0 && (
          <p className="py-8 text-center text-sm text-muted-foreground">
            Nothing matches those filters.
          </p>
        )}
      </div>
    </div>
  );
}

function Stat({
  label,
  value,
  icon,
  accent,
}: {
  label: string;
  value: number;
  icon: React.ReactNode;
  accent?: boolean;
}) {
  return (
    <Card>
      <CardContent className="p-3">
        <div className="flex items-center gap-1.5 text-muted-foreground">
          {icon}
          <span className="text-[11px] uppercase tracking-wide">{label}</span>
        </div>
        <div
          className={`mt-1 text-2xl font-semibold tabular-nums ${accent ? "text-severity-high" : ""}`}
        >
          {value}
        </div>
      </CardContent>
    </Card>
  );
}
