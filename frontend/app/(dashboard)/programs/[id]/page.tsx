"use client";

import { useCallback, useEffect, useState } from "react";
import { useParams } from "next/navigation";
import {
  Globe, CheckCircle2, ShieldCheck, Play, Copy, RefreshCw, KeyRound, Server, ShieldAlert, Clock,
} from "lucide-react";
import { api, type Asset, type Finding, type Program, type Verification } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { SeverityBadge } from "@/components/ui/badge";
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
  const [secrets, setSecrets] = useState<Record<string, unknown>[]>([]);
  const [deltas, setDeltas] = useState<Record<string, unknown>[]>([]);

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
  async function scan() {
    const res = await api.triggerScan(id);
    setMsg(`Scan ${res.status}.`);
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
            <Button onClick={scan}>
              <Play className="h-4 w-4" /> Run scan
            </Button>
          </div>
        )
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
            <Card key={f.fingerprint}>
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
          {assets.map((a) => (
            <Card key={a.fingerprint}>
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
                {a.ip_class && <span className="text-xs text-muted-foreground">{a.ip_class}</span>}
                <span className="text-xs text-muted-foreground">{timeAgo(a.first_seen)}</span>
              </CardContent>
            </Card>
          ))}
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
    </div>
  );
}

function Empty({ label }: { label: string }) {
  return <p className="py-8 text-center text-sm text-muted-foreground">{label}</p>;
}
