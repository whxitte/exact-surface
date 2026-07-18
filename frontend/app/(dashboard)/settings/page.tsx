"use client";

import { useEffect, useState } from "react";
import { KeyRound, Copy, Check } from "lucide-react";
import { api } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input, Label } from "@/components/ui/input";
import { NotificationsSettings } from "@/components/notifications-settings";
import { IntegrationsSettings } from "@/components/integrations-settings";
import { ScheduleDefaultsSettings } from "@/components/schedule-defaults-settings";
import { TimeoutDefaultsSettings } from "@/components/timeout-defaults-settings";
import { AlertPolicySettings } from "@/components/alert-policy-settings";

export default function SettingsPage() {
  const [me, setMe] = useState<{
    tenant_id: string;
    role: string;
    plan?: string;
    domain_limit?: number | null;
    domains_used?: number;
  } | null>(null);
  const [keyName, setKeyName] = useState("");
  const [newKey, setNewKey] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    api.me().then(setMe).catch(() => {});
  }, []);

  async function createKey(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    try {
      const res = await api.createApiKey(keyName.trim());
      setNewKey(res.api_key);
      setKeyName("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "failed");
    }
  }

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Settings</h1>
        <p className="text-sm text-muted-foreground">Account and API access.</p>
      </div>

      <Card>
        <CardContent className="p-5">
          <h2 className="mb-3 text-sm font-semibold">Account</h2>
          <dl className="grid grid-cols-2 gap-3 text-sm">
            <dt className="text-muted-foreground">Tenant</dt>
            <dd className="font-mono">{me?.tenant_id ?? "—"}</dd>
            <dt className="text-muted-foreground">Role</dt>
            <dd className="capitalize">{me?.role ?? "—"}</dd>
          </dl>
        </CardContent>
      </Card>

      <Card>
        <CardContent className="p-5">
          <div className="mb-3 flex items-center justify-between">
            <h2 className="text-sm font-semibold">Plan</h2>
            <span className="rounded-full bg-primary/10 px-2.5 py-0.5 text-xs font-medium capitalize text-primary">
              {me?.plan ?? "—"}
            </span>
          </div>
          {(() => {
            const used = me?.domains_used ?? 0;
            const limit = me?.domain_limit; // undefined until loaded, null = unlimited
            const cap = limit == null ? Infinity : limit;
            const pct = cap === Infinity ? 0 : Math.min(100, (used / Math.max(cap, 1)) * 100);
            const atLimit = used >= cap;
            return (
              <>
                <div className="flex items-baseline justify-between text-sm">
                  <span className="text-muted-foreground">Domains</span>
                  <span className="font-mono">
                    {used} / {limit == null ? "∞" : limit}
                  </span>
                </div>
                {limit != null && (
                  <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-muted">
                    <div
                      className={`h-full rounded-full ${atLimit ? "bg-severity-high" : "bg-primary"}`}
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                )}
                <p className="mt-3 text-xs text-muted-foreground">
                  {atLimit
                    ? "You've used your plan's domain allowance. Remove a domain or upgrade to add another."
                    : "Free 1 · Pro 5 · Business 25 · Enterprise unlimited. The limit is enforced when you add a domain."}
                </p>
              </>
            );
          })()}
        </CardContent>
      </Card>

      <Card>
        <CardContent className="space-y-4 p-5">
          <div className="flex items-center gap-2">
            <KeyRound className="h-4 w-4 text-primary" />
            <h2 className="text-sm font-semibold">API keys</h2>
          </div>
          <form onSubmit={createKey} className="flex items-end gap-3">
            <div className="flex-1">
              <Label htmlFor="keyname">Key name</Label>
              <Input id="keyname" value={keyName} onChange={(e) => setKeyName(e.target.value)}
                placeholder="ci-pipeline" required />
            </div>
            <Button type="submit">Generate key</Button>
          </form>
          {error && <p className="text-sm text-severity-critical">{error}</p>}

          {newKey && (
            <div className="space-y-2 rounded-md border border-primary/30 bg-primary/10 p-3">
              <p className="text-xs text-primary">
                Copy this key now — it will not be shown again.
              </p>
              <div className="flex items-center gap-2 font-mono text-xs">
                <span className="flex-1 break-all">{newKey}</span>
                <button
                  onClick={() => {
                    navigator.clipboard?.writeText(newKey);
                    setCopied(true);
                    setTimeout(() => setCopied(false), 1500);
                  }}
                >
                  {copied ? (
                    <Check className="h-4 w-4 text-primary" />
                  ) : (
                    <Copy className="h-4 w-4 text-muted-foreground hover:text-foreground" />
                  )}
                </button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      <AlertPolicySettings />

      <ScheduleDefaultsSettings />

      <TimeoutDefaultsSettings />

      <IntegrationsSettings />

      <NotificationsSettings />
    </div>
  );
}
