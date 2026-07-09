"use client";

import { useCallback, useEffect, useState } from "react";
import { useParams } from "next/navigation";
import {
  Globe, CheckCircle2, ShieldCheck, Play, Pause, Copy, RefreshCw, KeyRound, Server, ShieldAlert,
  Clock, Eye, EyeOff, FileText, FileCode, FileBarChart, FileType,
} from "lucide-react";
import {
  api, downloadReport,
  type Asset, type Finding, type Program, type Secret, type Verification,
} from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { SeverityBadge } from "@/components/ui/badge";
import { Modal } from "@/components/ui/modal";
import { severityRank } from "@/lib/severity";
import { timeAgo } from "@/lib/utils";

type Tab = "findings" | "assets" | "secrets" | "timeline";

export default function ProgramDetail() {
  const { id } = useParams<{ id: string }>();
  const [program, setProgram] = useState<Program | null>(null);
  const [verify, setVerify] = useState<Verification | null>(null);
  const [msg, setMsg] = useState("");
  const [tab, setTab] = useState<Tab>("findings");
  const [findings, setFindings] = useState<Finding[]>([]);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [secrets, setSecrets] = useState<Secret[]>([]);
  const [deltas, setDeltas] = useState<Record<string, unknown>[]>([]);
  const [selected, setSelected] = useState<Finding | null>(null);
  const [reportBusy, setReportBusy] = useState("");
  const [scanBusy, setScanBusy] = useState(false);

  const loadProgram = useCallback(() => {
    api.getProgram(id).then(setProgram).catch((e) => setMsg(e.message));
  }, [id]);

  useEffect(loadProgram, [loadProgram]);

  useEffect(() => {
    if (!program) return;
    api.listFindings(id).then(setFindings).catch(() => {});
    api.listAssets(id).then(setAssets).catch(() => {});
    api.listSecrets(id).then(setSecrets).catch(() => {});
    api.listDeltas(id).then(setDeltas).catch(() => {});
  }, [program, id]);

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
    setMsg("Authorization recorded. You can scan now.");
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
          <div className="flex gap-3">
            <Button onClick={authorize} variant="secondary">
              <ShieldCheck className="h-4 w-4" /> Authorize scanning
            </Button>
            <Button onClick={scan} disabled={scanBusy}>
              <Play className="h-4 w-4" /> {scanBusy ? "Starting…" : "Run scan"}
            </Button>
            <label className="flex cursor-pointer items-center gap-2 text-xs text-muted-foreground">
              <input
                type="checkbox"
                checked={!!program.scan_shared_infra}
                onChange={(e) => toggleSharedInfra(e.target.checked)}
              />
              Scan my cloud infra (ports/content/active on cloud IPs — §9b)
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
                <label key={mod} className="flex cursor-pointer items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={(program.enabled_modules || []).includes(mod)}
                    onChange={(e) => toggleModule(mod, e.target.checked)}
                  />
                  <span>{label}</span>
                  <span className="text-xs text-muted-foreground">— {hint}</span>
                </label>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

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
      <div className="flex gap-1 border-b border-border">
        {([
          ["findings", ShieldAlert, findings.length],
          ["assets", Server, assets.length],
          ["secrets", KeyRound, secrets.length],
          ["timeline", Clock, deltas.length],
        ] as const).map(([key, Icon, count]) => (
          <button
            key={key}
            onClick={() => setTab(key)}
            className={`flex items-center gap-2 border-b-2 px-4 py-2 text-sm capitalize transition-colors ${
              tab === key
                ? "border-primary text-foreground"
                : "border-transparent text-muted-foreground hover:text-foreground"
            }`}
          >
            <Icon className="h-4 w-4" /> {key}
            <span className="rounded-full bg-muted px-1.5 text-xs">{count}</span>
          </button>
        ))}
      </div>

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
                <span className="text-xs text-muted-foreground">{f.module}</span>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {tab === "assets" && (
        <div className="space-y-2">
          {assets.length === 0 && <Empty label="No assets discovered yet." />}
          {assets.map((a) => {
            const muted = a.monitored === false;
            return (
              <Card key={a.fingerprint} className={muted ? "opacity-60" : undefined}>
                <CardContent className="flex items-center gap-4 p-4">
                  <div className="min-w-0 flex-1">
                    <div className="truncate font-medium">{a.hostname}</div>
                    <div className="truncate font-mono text-xs text-muted-foreground">
                      {a.resolved_ips.join(", ") || "unresolved"}
                    </div>
                  </div>
                  {a.is_ephemeral && (
                    <span className="rounded-full bg-severity-medium/15 px-2 py-0.5 text-xs text-severity-medium">
                      ephemeral
                    </span>
                  )}
                  {a.ip_class && (
                    <span className="text-xs text-muted-foreground">{a.ip_class}</span>
                  )}
                  <span className="text-xs text-muted-foreground">{timeAgo(a.first_seen)}</span>
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
                    {muted ? "Muted" : "Monitored"}
                  </button>
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

      {tab === "timeline" && (
        <div className="space-y-2">
          {deltas.length === 0 && <Empty label="No changes recorded yet." />}
          {deltas.map((d, i) => (
            <Card key={i}>
              <CardContent className="flex items-center gap-4 p-4">
                <Clock className="h-4 w-4 text-muted-foreground" />
                <div className="flex-1">
                  <span className="font-medium">{String(d.kind)}</span>{" "}
                  <span className="text-sm text-muted-foreground">
                    {String(d.before ?? "")} → {String(d.after ?? "")}
                  </span>
                </div>
                <span className="text-xs text-muted-foreground">{timeAgo(String(d.observed_at))}</span>
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
