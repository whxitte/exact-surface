"use client";

import { useEffect, useState } from "react";
import { BellRing, Save, RotateCcw } from "lucide-react";
import { api, type AlertPolicy, type AlertPolicyValues } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { Select } from "@/components/ui/select";
import { NumberInput } from "@/components/ui/number-input";
import { Input } from "@/components/ui/input";

/** Alert policy editor. Account-wide defaults when `programId` is omitted, else the
 *  per-program override (which falls back to the account defaults). */
export function AlertPolicySettings({ programId }: { programId?: string }) {
  const [data, setData] = useState<AlertPolicy | null>(null);
  const [v, setV] = useState<AlertPolicyValues | null>(null);
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState("");

  function seed(d: AlertPolicy) {
    // program: start from what notify actually enforces; account: defaults + overrides
    const base = d.effective ?? { ...d.defaults, ...d.alert_policy };
    setV(base as AlertPolicyValues);
  }

  function load() {
    const p = programId ? api.getAlertPolicy(programId) : api.getAlertPolicyDefaults();
    p.then((d) => {
      setData(d);
      seed(d);
    }).catch((e) => setMsg(e.message));
  }
  useEffect(load, [programId]);

  async function save() {
    if (!v) return;
    setSaving(true);
    setMsg("");
    try {
      const next = programId
        ? await api.setAlertPolicy(programId, v)
        : await api.setAlertPolicyDefaults(v);
      setData(next);
      seed(next);
      setMsg("Saved.");
    } catch (e) {
      setMsg(e instanceof Error ? e.message : "failed");
    } finally {
      setSaving(false);
    }
  }

  async function reset() {
    setSaving(true);
    setMsg("");
    try {
      const next = programId
        ? await api.setAlertPolicy(programId, {})
        : await api.setAlertPolicyDefaults({});
      setData(next);
      seed(next);
      setMsg(programId ? "Cleared — inherits account defaults." : "Reset to defaults.");
    } catch (e) {
      setMsg(e instanceof Error ? e.message : "failed");
    } finally {
      setSaving(false);
    }
  }

  if (!data || !v) return null;
  const hasCustom = Object.keys(data.alert_policy ?? {}).length > 0;
  const set = <K extends keyof AlertPolicyValues>(k: K, val: AlertPolicyValues[K]) =>
    setV((prev) => (prev ? { ...prev, [k]: val } : prev));

  const family = (
    key: keyof AlertPolicyValues,
    label: string,
    hint: string,
    extra?: React.ReactNode,
  ) => (
    <div className="rounded-md border border-border px-3 py-2.5">
      <div className="flex items-center gap-3">
        <div className="min-w-0 flex-1">
          <div className="text-sm">{label}</div>
          <div className="text-xs text-muted-foreground">{hint}</div>
        </div>
        <Switch checked={!!v[key]} onChange={(c) => set(key, c as never)} />
      </div>
      {extra && !!v[key] && <div className="mt-2.5 border-t border-border/60 pt-2.5">{extra}</div>}
    </div>
  );

  return (
    <Card>
      <CardContent className="space-y-4 p-5">
        <div className="flex items-center gap-2">
          <BellRing className="h-4 w-4 text-primary" />
          <h2 className="text-sm font-semibold">
            {programId ? "Alert policy" : "Default alert policy"}
          </h2>
          {hasCustom && programId && (
            <span className="rounded-full bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground">
              custom
            </span>
          )}
        </div>
        <p className="text-xs text-muted-foreground">
          What gets sent to your notification channels.{" "}
          {programId
            ? "Overrides your account defaults for this domain."
            : "Applies to every domain unless it sets its own."}
        </p>

        {/* severity floor */}
        <div className="flex items-center gap-3 rounded-md border border-border px-3 py-2.5">
          <div className="min-w-0 flex-1">
            <div className="text-sm">Minimum severity</div>
            <div className="text-xs text-muted-foreground">
              Only alert on findings / secrets / leaks / CVEs at or above this level.
            </div>
          </div>
          <Select
            value={v.finding_min_severity}
            onChange={(e) => set("finding_min_severity", e.target.value)}
            className="h-8 w-32 capitalize"
          >
            {data.severities.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </Select>
        </div>

        <div className="grid gap-2 sm:grid-cols-2">
          {family("alert_findings", "Vulnerability findings", "nuclei, takeover, dorks")}
          {family("alert_secrets", "Exposed secrets", "keys/tokens found in responses")}
          {family("alert_leaks", "Public leaks", "GitHub / OSINT credential leaks")}
          {family(
            "alert_cves",
            "CVE matches",
            "known CVEs on detected tech",
            <label className="flex items-center gap-2 text-xs text-muted-foreground">
              Min CVSS
              <NumberInput
                min={0}
                max={10}
                value={v.cve_min_cvss}
                onChange={(val) => set("cve_min_cvss", Math.min(10, Math.max(0, val)))}
              />
              <span>(0 = any)</span>
            </label>,
          )}
          {family(
            "alert_new_assets",
            "New subdomains",
            "a subdomain appears after the baseline scan",
          )}
          {family(
            "alert_new_ports",
            "New open ports",
            "a port opens after the baseline scan",
            <label className="flex flex-col gap-1 text-xs text-muted-foreground">
              Only these ports (nmap-style, blank = any)
              <Input
                value={v.port_filter}
                onChange={(e) => set("port_filter", e.target.value)}
                placeholder="22,80,443 or 1-1024"
                className="h-8 font-mono"
              />
            </label>,
          )}
        </div>

        <div className="flex items-center gap-3">
          <Button onClick={save} disabled={saving}>
            <Save className="h-4 w-4" /> {saving ? "Saving…" : "Save"}
          </Button>
          <Button variant="outline" onClick={reset} disabled={saving || (!!programId && !hasCustom)}>
            <RotateCcw className="h-4 w-4" /> {programId ? "Use account defaults" : "Reset"}
          </Button>
          {msg && <span className="text-sm text-muted-foreground">{msg}</span>}
        </div>
      </CardContent>
    </Card>
  );
}
