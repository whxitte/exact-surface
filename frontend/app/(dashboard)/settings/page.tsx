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
import { AccessManagementSettings } from "@/components/access-management-settings";

export default function SettingsPage() {
  const [me, setMe] = useState<{
    tenant_id: string;
    role: string;
    is_owner?: boolean;
    permissions?: string[];
  } | null>(null);
  const [keyName, setKeyName] = useState("");
  const [newKey, setNewKey] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    api.me().then(setMe).catch(() => {});
  }, []);

  // The settings sub-sections below all require the "settings.manage" permission
  // server-side (the owner always has it). Hiding them from a viewer keeps the page
  // from filling with 403 errors and matches exactly what the API will allow.
  const canManageSettings = !!me && (me.is_owner || (me.permissions ?? []).includes("settings.manage"));

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

      {me?.is_owner && <AccessManagementSettings />}

      {canManageSettings && (
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
      )}

      {canManageSettings && (
        <>
          <AlertPolicySettings />

          <ScheduleDefaultsSettings />

          <TimeoutDefaultsSettings />

          <IntegrationsSettings />

          <NotificationsSettings />
        </>
      )}
    </div>
  );
}
