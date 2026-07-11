"use client";

import { useCallback, useEffect, useState } from "react";
import { useParams } from "next/navigation";
import {
  Globe, CheckCircle2, ShieldCheck, Play, Pause, Copy, RefreshCw, KeyRound, Server, ShieldAlert,
  Activity, Eye, EyeOff, Link2, Network, FileText, FileCode, FileBarChart, FileType,
  Bug, GitBranch, Boxes, Clock,
} from "lucide-react";
import {
  api, downloadReport,
  type Asset, type Correlation, type Cve, type Endpoint, type Finding, type Leak,
  type Port, type Program, type Secret, type Verification,
} from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { ScheduleCard } from "@/components/schedule-card";
import { AlertPolicySettings } from "@/components/alert-policy-settings";
import { AttackSurfaceView } from "@/components/attack-surface-view";
import { SeverityBadge } from "@/components/ui/badge";
import { Modal } from "@/components/ui/modal";
import { severityRank } from "@/lib/severity";
import { timeAgo } from "@/lib/utils";

type Tab =
  | "surface" | "priorities" | "findings" | "cves" | "assets"
  | "endpoints" | "ports" | "secrets" | "leaks";

export default function ProgramDetail() {
  const { id } = useParams<{ id: string }>();
  const [program, setProgram] = useState<Program | null>(null);
  const [verify, setVerify] = useState<Verification | null>(null);
  const [msg, setMsg] = useState("");
  const [tab, setTab] = useState<Tab>("surface");
  const [findings, setFindings] = useState<Finding[]>([]);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [endpoints, setEndpoints] = useState<Endpoint[]>([]);
  const [ports, setPorts] = useState<Port[]>([]);
  const [secrets, setSecrets] = useState<Secret[]>([]);
  const [cves, setCves] = useState<Cve[]>([]);
  const [leaks, setLeaks] = useState<Leak[]>([]);
  const [correlation, setCorrelation] = useState<Correlation | null>(null);
  const [selected, setSelected] = useState<Finding | null>(null);
  const [reportBusy, setReportBusy] = useState("");
  const [scanBusy, setScanBusy] = useState(false);
  const [authorized, setAuthorized] = useState<boolean | null>(null);
  const [assetSort, setAssetSort] = useState<"name" | "status" | "monitored" | "recent">("status");
  const [showSeen, setShowSeen] = useState(false);
  const [endpointSource, setEndpointSource] = useState<string>("all");

  const loadProgram = useCallback(() => {
    api.getProgram(id).then(setProgram).catch((e) => setMsg(e.message));
    // reflect whether scanning is already authorized (persisted) so the button
    // shows state instead of being endlessly re-clickable.
    api
      .getAuthorization(id)
      .then((a) => setAuthorized(!!a?.apex_verified && !a?.revoked))
      .catch(() => setAuthorized(false));
  }, [id]);

  useEffect(loadProgram, [loadProgram]);

  useEffect(() => {
    if (!program) return;
    api.listFindings(id).then(setFindings).catch(() => {});
    api.listAssets(id).then(setAssets).catch(() => {});
    api.listEndpoints(id).then(setEndpoints).catch(() => {});
    api.listPorts(id).then(setPorts).catch(() => {});
    api.listSecrets(id).then(setSecrets).catch(() => {});
    api.listCves(id).then(setCves).catch(() => {});
    api.listLeaks(id).then(setLeaks).catch(() => {});
    api.getCorrelation(id).then(setCorrelation).catch(() => {});
  }, [program, id]);

  // Derive per-asset live status/tech from its root endpoint (probe output), so the
  // assets view shows what an attacker sees: alive?, HTTP status, technologies.
  const endpointByHost = new Map<string, Endpoint>();
  for (const ep of endpoints) {
    try {
      const host = new URL(ep.url).hostname;
      const cur = endpointByHost.get(host);
      // prefer the shortest path (closest to the root) as the representative endpoint
      if (!cur || ep.url.length < cur.url.length) endpointByHost.set(host, ep);
    } catch {
      /* ignore unparseable urls */
    }
  }

  // asset fingerprint -> hostname, so the CVEs tab can name the affected host.
  const hostByAssetFp = new Map<string, string>();
  for (const a of assets) hostByAssetFp.set(a.fingerprint, a.hostname);

  // ip -> hostname(s), so the ports tab can show which subdomain a port belongs to.
  const hostsByIp = new Map<string, string[]>();
  for (const a of assets)
    for (const ip of a.resolved_ips || []) {
      const list = hostsByIp.get(ip) || [];
      if (!list.includes(a.hostname)) list.push(a.hostname);
      hostsByIp.set(ip, list);
    }

  const endpointSources = Array.from(
    new Set(endpoints.map((e) => e.source || "other")),
  ).sort();
  const shownEndpoints =
    endpointSource === "all"
      ? endpoints
      : endpoints.filter((e) => (e.source || "other") === endpointSource);

  const isAlive = (a: Asset) => endpointByHost.get(a.hostname)?.status_code != null;
  const sortedAssets = [...assets].sort((x, y) => {
    if (assetSort === "status") return Number(isAlive(y)) - Number(isAlive(x));
    if (assetSort === "monitored")
      return Number(y.monitored !== false) - Number(x.monitored !== false);
    if (assetSort === "recent")
      return Date.parse(y.first_seen || "") - Date.parse(x.first_seen || "");
    return x.hostname.localeCompare(y.hostname);
  });

  async function requestChallenge() {
    setMsg("");
    setVerify(await api.requestVerify(id, "dns_txt"));
  }
  async function checkChallenge() {
    setMsg("");
    const res = await api.checkVerify(id);
    setMsg(res.verified ? "Domain verified!" : `Not found yet: ${res.detail}`);
    if (res.verified) loadProgram();
  }
  async function authorize() {
    await api.createAuthorization(id);
    setAuthorized(true);
    setMsg("Scanning authorized — you (the owner) have consented to active scanning of this domain.");
  }
  async function toggleSharedInfra(value: boolean) {
    try {
      await api.setScanSharedInfra(id, value);
      setMsg(
        value
          ? "Cloud-scanning authorized: ports, content discovery & active scans will run on your cloud/public IPs (CDNs and internal ranges stay off)."
          : "Cloud-scanning turned off: shared-infra hosts are HTTP-probe only.",
      );
      loadProgram();
    } catch (e) {
      setMsg((e as Error).message || "Could not update scan config.");
    }
  }
  async function toggleModule(mod: string, on: boolean) {
    const current = program?.enabled_modules || [];
    const next = on ? [...new Set([...current, mod])] : current.filter((m) => m !== mod);
    try {
      await api.setModules(id, next);
      loadProgram();
    } catch (e) {
      setMsg((e as Error).message || "Could not update modules.");
    }
  }
  async function toggleMonitoring() {
    if (!program) return;
    try {
      await api.setMonitoring(id, !program.enabled);
      loadProgram();
    } catch (e) {
      setMsg((e as Error).message || "Could not update monitoring.");
    }
  }
  async function toggleAssetMonitoring(a: Asset) {
    const next = a.monitored === false;
    try {
      await api.setAssetMonitoring(id, a.fingerprint, next);
      setAssets((prev) =>
        prev.map((x) => (x.fingerprint === a.fingerprint ? { ...x, monitored: next } : x)),
      );
    } catch (e) {
      setMsg((e as Error).message || "Could not update asset.");
    }
  }
  async function scan() {
    setScanBusy(true);
    try {
      const res = await api.triggerScan(id);
      setMsg(res.detail || `Scan ${res.status}.`);
      // Give the worker a moment, then refresh findings/assets to show new results.
      setTimeout(() => {
        api.listFindings(id).then(setFindings).catch(() => {});
        api.listAssets(id).then(setAssets).catch(() => {});
      }, 8000);
    } catch (e) {
      // 409 = a scan is already running for this program (backend-enforced).
      setMsg((e as Error).message || "Could not start scan.");
    } finally {
      setScanBusy(false);
    }
  }
  async function download(fmt: string) {
    setReportBusy(fmt);
    try {
      await downloadReport(id, fmt);
    } catch (e) {
      setMsg(e instanceof Error ? e.message : "report failed");
    } finally {
      setReportBusy("");
    }
  }

  const sortedFindings = [...findings].sort(
    (a, b) => severityRank(a.severity) - severityRank(b.severity),
  );

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <div className="flex h-10 w-10 items-center justify-center rounded-md bg-muted text-muted-foreground">
          <Globe className="h-5 w-5" />
        </div>
        <div className="flex-1">
          <h1 className="text-xl font-semibold tracking-tight">{program?.apex_domain ?? "…"}</h1>
          <div className="text-xs text-muted-foreground">{id}</div>
        </div>
        {program?.verified && (
          <span className="flex items-center gap-1.5 text-sm text-primary">
            <CheckCircle2 className="h-4 w-4" /> Verified
          </span>
        )}
        {program && (
          <button
            onClick={toggleMonitoring}
            className={`flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-xs transition-colors ${
              program.enabled === false
                ? "border-border text-muted-foreground hover:text-foreground"
                : "border-primary/40 text-primary"
            }`}
            title={program.enabled === false ? "Monitoring paused — click to resume" : "Monitoring active — click to pause"}
          >
            {program.enabled === false ? (
              <>
                <Pause className="h-3.5 w-3.5" /> Paused
              </>
            ) : (
              <>
                <Play className="h-3.5 w-3.5" /> Monitoring
              </>
            )}
          </button>
        )}
      </div>

      {msg && (
        <div className="rounded-md border border-primary/30 bg-primary/10 px-4 py-2 text-sm text-primary">
          {msg}
        </div>
      )}

      {/* Onboarding actions */}
      {program && !program.verified ? (
        <Card>
          <CardContent className="space-y-4 p-5">
            <div className="flex items-center gap-2">
              <ShieldCheck className="h-4 w-4 text-primary" />
              <h2 className="font-semibold">Verify domain ownership</h2>
            </div>
            {!verify ? (
              <Button onClick={requestChallenge}>
                <KeyRound className="h-4 w-4" /> Generate DNS challenge
              </Button>
            ) : (
              <div className="space-y-3">
                <p className="text-sm text-muted-foreground">{verify.instructions}</p>
                <div className="flex items-center gap-2 rounded-md border border-border bg-background p-3 font-mono text-xs">
                  <span className="flex-1 break-all">{verify.token}</span>
                  <button onClick={() => navigator.clipboard?.writeText(verify.token)}>
                    <Copy className="h-4 w-4 text-muted-foreground hover:text-foreground" />
                  </button>
                </div>
                <Button onClick={checkChallenge} variant="secondary">
                  <RefreshCw className="h-4 w-4" /> Check verification
                </Button>
              </div>
            )}
          </CardContent>
        </Card>
      ) : (
        program && (
          <div className="flex flex-wrap items-center gap-3">
            {authorized ? (
              <span
                className="flex items-center gap-1.5 rounded-md border border-primary/40 px-3 py-1.5 text-sm text-primary"
                title="You have consented to active scanning of this domain. Required before scans run."
              >
                <ShieldCheck className="h-4 w-4" /> Scanning authorized
              </span>
            ) : (
              <Button
                onClick={authorize}
                variant="secondary"
                title="Consent to active scanning of this domain — required once before any scan runs."
              >
                <ShieldCheck className="h-4 w-4" /> Authorize scanning
              </Button>
            )}
            <Button onClick={scan} disabled={scanBusy || authorized === false}>
              <Play className="h-4 w-4" /> {scanBusy ? "Starting…" : "Run scan"}
            </Button>
            <label className="flex cursor-pointer items-center gap-3 text-xs text-muted-foreground ml-2">
              <Switch
                checked={!!program.scan_shared_infra}
                onChange={toggleSharedInfra}
              />
              <span>Scan my cloud infra (ports/content/active on cloud IPs — §9b)</span>
            </label>
          </div>
        )
      )}

      {/* Optional modules */}
      {program?.verified && (
        <Card>
          <CardContent className="p-4">
            <div className="mb-2 text-sm font-medium text-muted-foreground">Optional modules</div>
            <div className="flex flex-wrap gap-x-6 gap-y-2">
              {(
                [
                  ["tls", "TLS inspection", "cert chain + expiry (tlsx)"],
                  ["service_scan", "Service ID", "nmap -sV on open ports"],
                  ["dork", "Dorking", "search-engine exposures (needs Google CSE key)"],
                ] as const
              ).map(([mod, label, hint]) => (
                <label key={mod} className="flex cursor-pointer items-center gap-3 text-sm">
                  <Switch
                    checked={(program.enabled_modules || []).includes(mod)}
                    onChange={(val) => toggleModule(mod, val)}
                  />
                  <span>{label}</span>
                  <span className="text-xs text-muted-foreground">— {hint}</span>
                </label>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Scan schedule (cadence + last/next scan breakdown) */}
      {program?.verified && <ScheduleCard programId={id} />}

      {/* Alert policy (what pages this domain sends to channels) */}
      {program?.verified && <AlertPolicySettings programId={id} />}

      {/* Reports */}
      {program?.verified && (
        <Card>
          <CardContent className="flex flex-wrap items-center gap-3 p-4">
            <span className="mr-2 text-sm font-medium text-muted-foreground">Reports</span>
            {(
              [
                ["hackerone", "HackerOne", FileCode],
                ["executive", "Executive", FileBarChart],
                ["html", "HTML", FileText],
                ["pdf", "PDF", FileType],
              ] as const
            ).map(([fmt, label, Icon]) => (
              <Button
                key={fmt}
                variant="outline"
                size="sm"
                disabled={reportBusy === fmt}
                onClick={() => download(fmt)}
              >
                <Icon className="h-4 w-4" /> {reportBusy === fmt ? "…" : label}
              </Button>
            ))}
          </CardContent>
        </Card>
      )}

      {/* Tabs */}
      <div className="flex w-full gap-1 border-b border-border overflow-x-auto [scrollbar-width:none] [&::-webkit-scrollbar]:hidden whitespace-nowrap min-w-0">
        {([
          ["surface", Activity, null],
          ["priorities", GitBranch, correlation?.count ?? null],
          ["findings", ShieldAlert, findings.length],
          ["cves", Bug, cves.length],
          ["assets", Server, assets.length],
          ["endpoints", Link2, endpoints.length],
          ["ports", Network, ports.length],
          ["secrets", KeyRound, secrets.length],
          ["leaks", Boxes, leaks.length],
        ] as const).map(([key, Icon, count]) => (
          <button
            key={key}
            onClick={() => setTab(key)}
            className={`flex items-center gap-2 border-b-2 px-4 py-2 text-sm capitalize transition-colors shrink-0 ${
              tab === key
                ? "border-primary text-foreground"
                : "border-transparent text-muted-foreground hover:text-foreground"
            }`}
          >
            <Icon className="h-4 w-4" /> {key}
            {count != null && (
              <span className="rounded-full bg-muted px-1.5 text-xs">{count}</span>
            )}
          </button>
        ))}
      </div>

      {tab === "surface" && <AttackSurfaceView programId={id} />}

      {tab === "priorities" && (
        <div className="space-y-2">
          <p className="text-xs text-muted-foreground">
            Hosts ranked by combined risk across every signal (findings, secrets, leaks,
            CVEs, exposed ports). A <span className="text-primary">chain</span> is a host
            carrying two or more independent high-signal exposures — the attacker&apos;s
            best foothold.
          </p>
          {(!correlation || correlation.issues.length === 0) && (
            <Empty label="No correlated issues yet — run a scan to build the picture." />
          )}
          {correlation?.issues.map((it) => (
            <Card key={it.host}>
              <CardContent className="flex items-center gap-4 p-4">
                <div className="flex w-12 shrink-0 flex-col items-center">
                  <span className="text-lg font-bold tabular-nums">{it.risk_score}</span>
                  <span className="text-[10px] uppercase text-muted-foreground">risk</span>
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="truncate font-mono text-sm">{it.host}</span>
                    {it.is_chain && (
                      <span className="rounded-full bg-severity-high/15 px-2 py-0.5 text-[10px] font-semibold uppercase text-severity-high">
                        chain
                      </span>
                    )}
                  </div>
                  <div className="mt-1 flex flex-wrap gap-1">
                    {it.signals.map((sig, i) => (
                      <span key={i} className="rounded bg-muted px-1.5 py-0.5 font-mono text-[11px]">
                        {sig}
                      </span>
                    ))}
                  </div>
                </div>
                <SeverityBadge severity={it.highest_severity} />
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {tab === "findings" && (
        <div className="space-y-2">
          {sortedFindings.length === 0 && <Empty label="No findings yet — run a scan." />}
          {sortedFindings.map((f) => (
            <Card
              key={f.fingerprint}
              className="cursor-pointer transition-colors hover:border-primary/40"
              onClick={() => setSelected(f)}
            >
              <CardContent className="flex items-center gap-4 p-4">
                <SeverityBadge severity={f.severity} />
                <div className="min-w-0 flex-1">
                  <div className="truncate font-medium">{f.name}</div>
                  <div className="truncate font-mono text-xs text-muted-foreground">{f.location}</div>
                </div>
                {f.is_new && <span className="text-xs text-primary">NEW</span>}
                <span className="rounded bg-muted px-1.5 py-0.5 font-mono text-[11px] text-muted-foreground">
                  {f.module}
                </span>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {tab === "cves" && (
        <div className="space-y-2">
          {cves.length === 0 && (
            <Empty label="No CVE matches — detected tech is matched against the NVD/KEV feed each cycle." />
          )}
          {cves.map((c) => {
            const host = hostByAssetFp.get(c.asset_fingerprint);
            return (
              <Card key={c.fingerprint}>
                <CardContent className="flex items-center gap-4 p-4">
                  <SeverityBadge severity={c.severity} />
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <a
                        href={`https://nvd.nist.gov/vuln/detail/${c.cve_id}`}
                        target="_blank"
                        rel="noreferrer"
                        className="font-medium hover:text-primary hover:underline"
                      >
                        {c.cve_id}
                      </a>
                      {c.on_kev && (
                        <span className="rounded-full bg-severity-critical/15 px-2 py-0.5 text-[10px] font-semibold uppercase text-severity-critical">
                          KEV
                        </span>
                      )}
                      <span className="rounded bg-muted px-1.5 text-[10px] uppercase text-muted-foreground">
                        {c.confidence} confidence
                      </span>
                    </div>
                    <div className="truncate font-mono text-xs text-muted-foreground">
                      {host ? `${host} · ` : ""}{c.cpe}
                    </div>
                  </div>
                  {c.cvss != null && (
                    <span className="font-mono text-sm tabular-nums">CVSS {c.cvss.toFixed(1)}</span>
                  )}
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}

      {tab === "assets" && (
        <div className="space-y-2">
          {assets.length > 0 && (
            <div className="flex items-center justify-end gap-3 text-xs text-muted-foreground">
              <button
                onClick={() => setShowSeen((v) => !v)}
                aria-pressed={showSeen}
                title="Show when each subdomain first appeared and was last seen alive"
                className={`flex items-center gap-1.5 rounded-md border px-2 py-1 transition-colors ${
                  showSeen
                    ? "border-primary/40 text-primary"
                    : "border-border hover:text-foreground"
                }`}
              >
                <Clock className="h-3.5 w-3.5" />
                {showSeen ? "Hide lifespan" : "Show lifespan"}
              </button>
              <span>Sort by</span>
              <select
                value={assetSort}
                onChange={(e) => setAssetSort(e.target.value as typeof assetSort)}
                className="h-8 rounded-md border border-border bg-background px-2"
              >
                <option value="status">Alive first</option>
                <option value="monitored">Monitored first</option>
                <option value="recent">Newest</option>
                <option value="name">Name</option>
              </select>
            </div>
          )}
          {assets.length === 0 && <Empty label="No assets discovered yet." />}
          {sortedAssets.map((a) => {
            const muted = a.monitored === false;
            const ep = endpointByHost.get(a.hostname);
            const alive = ep?.status_code != null;
            return (
              <Card key={a.fingerprint} className={muted ? "opacity-60" : undefined}>
                <CardContent className="flex items-center gap-3 p-4">
                  <span
                    className={`h-2 w-2 shrink-0 rounded-full ${alive ? "bg-severity-low" : "bg-muted-foreground/40"}`}
                    title={alive ? "Alive (HTTP responded)" : "No HTTP response"}
                  />
                  <div className="min-w-0 flex-1">
                    <div className="truncate font-medium">{a.hostname}</div>
                    <div className="truncate font-mono text-xs text-muted-foreground">
                      {a.resolved_ips.join(", ") || "unresolved"}
                      {ep?.title ? ` · ${ep.title}` : ""}
                    </div>
                    {a.dns_records?.cname?.length ? (
                      <div className="truncate font-mono text-[11px] text-severity-medium">
                        CNAME → {a.dns_records.cname.join(", ")}
                      </div>
                    ) : null}
                    {(() => {
                      const extra = ["ns", "mx", "txt", "aaaa"]
                        .filter((k) => a.dns_records?.[k]?.length)
                        .map((k) => `${k.toUpperCase()} ${a.dns_records![k].length}`);
                      return extra.length ? (
                        <div className="truncate text-[11px] text-muted-foreground">
                          {extra.join(" · ")}
                        </div>
                      ) : null;
                    })()}
                  </div>
                  {showSeen && (
                    <div className="hidden shrink-0 flex-col items-end gap-0.5 text-[11px] text-muted-foreground sm:flex">
                      <span title={a.first_seen ? new Date(a.first_seen).toLocaleString() : ""}>
                        <span className="text-severity-low">↑ alive</span> {timeAgo(a.first_seen)}
                      </span>
                      <span title={a.last_seen ? new Date(a.last_seen).toLocaleString() : ""}>
                        <span className={alive ? "text-muted-foreground" : "text-severity-medium"}>
                          {alive ? "seen" : "↓ last"}
                        </span>{" "}
                        {timeAgo(a.last_seen)}
                      </span>
                    </div>
                  )}
                  {ep?.tech?.slice(0, 3).map((t) => (
                    <span key={t} className="rounded bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground">
                      {t}
                    </span>
                  ))}
                  {ep?.status_code != null && (
                    <span className="font-mono text-xs text-muted-foreground">{ep.status_code}</span>
                  )}
                  {a.is_ephemeral && (
                    <span className="rounded-full bg-severity-medium/15 px-2 py-0.5 text-xs text-severity-medium">
                      ephemeral
                    </span>
                  )}
                  {a.ip_class && (
                    <span className="hidden text-xs text-muted-foreground sm:inline">{a.ip_class}</span>
                  )}
                  <button
                    onClick={() => toggleAssetMonitoring(a)}
                    title={muted ? "Muted — click to monitor" : "Monitored — click to mute"}
                    className={`flex items-center gap-1 rounded-md px-2 py-1 text-xs transition-colors ${
                      muted
                        ? "text-muted-foreground hover:text-foreground"
                        : "text-primary hover:text-primary/80"
                    }`}
                  >
                    {muted ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                    <span className="hidden sm:inline">{muted ? "Muted" : "Monitored"}</span>
                  </button>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}

      {tab === "endpoints" && (
        <div className="space-y-2">
          {endpoints.length > 0 && (
            <div className="flex flex-wrap items-center gap-2">
              {["all", ...endpointSources].map((s) => (
                <button
                  key={s}
                  onClick={() => setEndpointSource(s)}
                  className={`rounded-full border px-3 py-1 text-xs capitalize transition-colors ${
                    endpointSource === s
                      ? "border-primary bg-primary/10 text-primary"
                      : "border-border text-muted-foreground hover:text-foreground"
                  }`}
                >
                  {s === "all" ? "all" : s}
                  <span className="ml-1.5 opacity-60">
                    {s === "all"
                      ? endpoints.length
                      : endpoints.filter((e) => (e.source || "other") === s).length}
                  </span>
                </button>
              ))}
            </div>
          )}
          {endpoints.length === 0 && <Empty label="No endpoints discovered yet — probe/crawl first." />}
          {shownEndpoints.map((ep) => (
            <Card key={ep.fingerprint}>
              <CardContent className="flex items-center gap-3 p-3">
                <span className="rounded bg-muted px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground">
                  {ep.method}
                </span>
                <a
                  href={ep.url}
                  target="_blank"
                  rel="noreferrer"
                  className="min-w-0 flex-1 truncate font-mono text-xs text-primary hover:underline"
                >
                  {ep.url}
                </a>
                {ep.source && (
                  <span className="hidden rounded bg-muted px-1.5 py-0.5 text-[10px] capitalize text-muted-foreground sm:inline">
                    {ep.source}
                  </span>
                )}
                {ep.tech?.slice(0, 2).map((t) => (
                  <span key={t} className="hidden rounded bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground md:inline">
                    {t}
                  </span>
                ))}
                {ep.status_code != null && (
                  <span className="font-mono text-xs text-muted-foreground">{ep.status_code}</span>
                )}
                <span className="hidden text-xs text-muted-foreground md:inline">
                  {timeAgo(ep.first_seen)}
                </span>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {tab === "ports" && (
        <div className="space-y-2">
          {ports.length === 0 && (
            <Empty label="No open ports — port scanning runs on confirmed-dedicated infra only (§9b)." />
          )}
          {ports.map((p) => {
            const hosts = hostsByIp.get(p.ip) || [];
            return (
              <Card key={p.fingerprint}>
                <CardContent className="flex items-center gap-3 p-3">
                  <span className="font-mono text-sm">
                    {p.ip}
                    <span className="text-primary">:{p.port}</span>
                    <span className="text-muted-foreground">/{p.protocol}</span>
                  </span>
                  <div className="min-w-0 flex-1">
                    {hosts.length > 0 && (
                      <div className="truncate text-xs">
                        {hosts[0]}
                        {hosts.length > 1 && (
                          <span className="text-muted-foreground"> +{hosts.length - 1} more</span>
                        )}
                      </div>
                    )}
                    <div className="truncate text-xs text-muted-foreground">
                      {p.service || "—"}
                      {p.product ? ` · ${p.product}${p.version ? ` ${p.version}` : ""}` : ""}
                    </div>
                  </div>
                  <span className="hidden text-xs text-muted-foreground md:inline">
                    {timeAgo(p.first_seen)}
                  </span>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}

      {tab === "secrets" && (
        <div className="space-y-2">
          {secrets.length === 0 && <Empty label="No exposed secrets found." />}
          {secrets.map((s, i) => (
            <Card key={i}>
              <CardContent className="flex items-center gap-4 p-4">
                <KeyRound className="h-4 w-4 text-severity-high" />
                <div className="min-w-0 flex-1">
                  <div className="font-medium">{String(s.kind)}</div>
                  <div className="truncate font-mono text-xs text-muted-foreground">
                    {String(s.source_locator ?? "")}
                  </div>
                </div>
                <span className="font-mono text-sm">{String(s.masked)}</span>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {tab === "leaks" && (
        <div className="space-y-2">
          {leaks.length === 0 && (
            <Empty label="No public leaks — GitHub/OSINT sources are searched for exposed credentials each cycle." />
          )}
          {leaks.map((l) => (
            <Card key={l.fingerprint}>
              <CardContent className="flex items-center gap-4 p-4">
                <SeverityBadge severity={l.severity} />
                <div className="min-w-0 flex-1">
                  <div className="font-medium">{l.kind}</div>
                  <div className="truncate font-mono text-xs text-muted-foreground">
                    {l.repo ? `${l.repo} · ` : ""}{l.source}
                  </div>
                </div>
                {l.url && (
                  <a
                    href={l.url}
                    target="_blank"
                    rel="noreferrer"
                    className="text-xs text-primary hover:underline"
                  >
                    view
                  </a>
                )}
                <span className="font-mono text-sm">{l.masked}</span>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      <Modal
        open={!!selected}
        onClose={() => setSelected(null)}
        title={
          selected && (
            <span className="flex items-center gap-2">
              <SeverityBadge severity={selected.severity} /> {selected.name}
            </span>
          )
        }
      >
        {selected && (
          <div className="space-y-4 text-sm">
            <Field label="Location">
              <code className="break-all text-xs">{selected.location}</code>
            </Field>
            <Field label="Detection">
              {selected.module} / <code className="text-xs">{selected.check_id}</code>
            </Field>
            {selected.description && (
              <Field label="Description">{selected.description}</Field>
            )}
            <Field label="Reproduce">
              <pre className="overflow-x-auto rounded-md border border-border bg-background p-3 text-xs">
                curl -i {selected.location}
              </pre>
            </Field>
            {selected.references && selected.references.length > 0 && (
              <Field label="References">
                <ul className="list-inside list-disc space-y-1">
                  {selected.references.map((r) => (
                    <li key={r}>
                      <a href={r} target="_blank" rel="noreferrer" className="text-primary hover:underline">
                        {r}
                      </a>
                    </li>
                  ))}
                </ul>
              </Field>
            )}
          </div>
        )}
      </Modal>
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="mb-1 text-xs uppercase tracking-wide text-muted-foreground">{label}</div>
      <div>{children}</div>
    </div>
  );
}

function Empty({ label }: { label: string }) {
  return <p className="py-8 text-center text-sm text-muted-foreground">{label}</p>;
}
