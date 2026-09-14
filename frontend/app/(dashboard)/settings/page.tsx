"use client";

import { useEffect, useState } from "react";
import { KeyRound, Copy, Check, ScrollText, Trash2 } from "lucide-react";
import { api, type ApiKeyInfo, type ScopeInfo, type AuditEvent } from "@/lib/api";
import { timeAgo } from "@/lib/utils";
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
  const [newKey, setNewKey] = useState<{ raw: string; scopes: string[] } | null>(null);
  const [scopeCatalogue, setScopeCatalogue] = useState<ScopeInfo[]>([]);
  const [chosenScopes, setChosenScopes] = useState<Set<string>>(() => new Set());
  const [keys, setKeys] = useState<ApiKeyInfo[]>([]);
  const [audit, setAudit] = useState<AuditEvent[]>([]);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    api.me().then(setMe).catch(() => {});
  }, []);

  // The settings sub-sections below all require the "settings.manage" permission
  // server-side (the owner always has it). Hiding them from a viewer keeps the page
  // from filling with 403 errors and matches exactly what the API will allow.
  const canManageSettings = !!me && (me.is_owner || (me.permissions ?? []).includes("settings.manage"));

  const reloadKeys = () => api.listApiKeys().then(setKeys).catch(() => {});
  const reloadAudit = () => api.auditEvents(50).then((r) => setAudit(r.events)).catch(() => {});
  useEffect(() => {
    if (!canManageSettings) return;
    api.apiKeyScopes().then((r) => setScopeCatalogue(r.scopes)).catch(() => {});
    reloadKeys();
    reloadAudit();
  }, [canManageSettings]);

  async function revokeKey(k: ApiKeyInfo) {
    if (!window.confirm(`Revoke "${k.name}" (${k.prefix}…)? Anything using it stops working immediately.`)) return;
    try {
      await api.revokeApiKey(k.key_id);
      reloadKeys();
      reloadAudit();
    } catch (err) {
      setError(err instanceof Error ? err.message : "failed");
    }
  }

  async function createKey(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    try {
      const res = await api.createApiKey(keyName.trim(), [...chosenScopes]);
      setNewKey({ raw: res.api_key, scopes: res.scopes });
      setKeyName("");
      setChosenScopes(new Set());
      reloadKeys();
      reloadAudit();
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
          <p className="text-xs text-muted-foreground">
            A key acts as you, narrowed to the scopes you pick. Read-only by default — the
            right posture for a CI job, an integration or an AI agent. Whatever the scopes, a
            key can never verify a domain, change scan-scope switches, delete a program, or
            manage members and keys: those need a person in a session.
          </p>
          <form onSubmit={createKey} className="space-y-3">
            <div className="flex items-end gap-3">
              <div className="flex-1">
                <Label htmlFor="keyname">Key name</Label>
                <Input id="keyname" value={keyName} onChange={(e) => setKeyName(e.target.value)}
                  placeholder="ci-pipeline" required />
              </div>
              <Button type="submit">Generate key</Button>
            </div>
            {scopeCatalogue.length > 0 && (
              <div className="grid gap-1.5 sm:grid-cols-2">
                {scopeCatalogue.map((sc) => {
                  const isRead = sc.scope === "read";
                  const on = isRead || chosenScopes.has(sc.scope);
                  return (
                    <label
                      key={sc.scope}
                      className={`flex cursor-pointer items-start gap-2 rounded-md border px-3 py-2 text-xs ${
                        !sc.grantable ? "cursor-not-allowed opacity-50" : on ? "border-primary/50 bg-primary/5" : "border-border"
                      }`}
                    >
                      <input
                        type="checkbox"
                        className="mt-0.5"
                        checked={on}
                        disabled={isRead || !sc.grantable}
                        onChange={(e) =>
                          setChosenScopes((prev) => {
                            const next = new Set(prev);
                            if (e.target.checked) next.add(sc.scope);
                            else next.delete(sc.scope);
                            return next;
                          })
                        }
                      />
                      <span>
                        <span className="font-medium">{sc.label}</span>
                        <span className="ml-1.5 font-mono text-[10px] text-muted-foreground">{sc.scope}</span>
                        <span className="block text-muted-foreground">{sc.description}</span>
                      </span>
                    </label>
                  );
                })}
              </div>
            )}
          </form>
          {error && <p className="text-sm text-severity-critical">{error}</p>}

          {newKey && (
            <div className="space-y-2 rounded-md border border-primary/30 bg-primary/10 p-3">
              <p className="text-xs text-primary">
                Copy this key now — it will not be shown again. Scopes granted:{" "}
                <span className="font-mono">{newKey.scopes.join(", ")}</span>
              </p>
              <div className="flex items-center gap-2 font-mono text-xs">
                <span className="flex-1 break-all">{newKey.raw}</span>
                <button
                  onClick={() => {
                    navigator.clipboard?.writeText(newKey.raw);
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

          {keys.length > 0 && (
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead className="text-left text-muted-foreground">
                  <tr>
                    <th className="py-1.5 pr-3 font-medium">Name</th>
                    <th className="py-1.5 pr-3 font-medium">Prefix</th>
                    <th className="py-1.5 pr-3 font-medium">Scopes</th>
                    <th className="py-1.5 pr-3 font-medium">Last used</th>
                    <th className="py-1.5 font-medium"></th>
                  </tr>
                </thead>
                <tbody>
                  {keys.map((k) => (
                    <tr key={k.key_id} className={`border-t border-border ${k.revoked_at ? "opacity-50" : ""}`}>
                      <td className="py-1.5 pr-3">{k.name}{k.revoked_at && <span className="ml-1.5 text-severity-critical">revoked</span>}</td>
                      <td className="py-1.5 pr-3 font-mono">{k.prefix}…</td>
                      <td className="py-1.5 pr-3 font-mono text-[10px]">{k.scopes.join(" ")}</td>
                      <td className="py-1.5 pr-3 text-muted-foreground">{k.last_used_at ? timeAgo(k.last_used_at) : "never"}</td>
                      <td className="py-1.5 text-right">
                        {!k.revoked_at && (
                          <button onClick={() => revokeKey(k)} title="Revoke" className="text-muted-foreground hover:text-severity-critical">
                            <Trash2 className="h-3.5 w-3.5" />
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>
      )}

      {canManageSettings && (
      <Card>
        <CardContent className="space-y-3 p-5">
          <div className="flex items-center gap-2">
            <ScrollText className="h-4 w-4 text-primary" />
            <h2 className="text-sm font-semibold">Audit log</h2>
            <span className="text-xs text-muted-foreground">every change, by whom, succeeded or refused</span>
          </div>
          {audit.length === 0 ? (
            <p className="text-xs text-muted-foreground">Nothing yet.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead className="text-left text-muted-foreground">
                  <tr>
                    <th className="py-1.5 pr-3 font-medium">When</th>
                    <th className="py-1.5 pr-3 font-medium">Actor</th>
                    <th className="py-1.5 pr-3 font-medium">Action</th>
                    <th className="py-1.5 pr-3 font-medium">Program</th>
                    <th className="py-1.5 font-medium">Result</th>
                  </tr>
                </thead>
                <tbody>
                  {audit.map((e) => (
                    <tr key={e.event_id} className="border-t border-border">
                      <td className="py-1.5 pr-3 text-muted-foreground whitespace-nowrap">{timeAgo(e.ts)}</td>
                      <td className="py-1.5 pr-3 font-mono text-[10px]">
                        {e.actor_type === "apikey" ? `key ${e.key_id}` : e.actor_id ?? "—"}
                      </td>
                      <td className="py-1.5 pr-3">
                        <span className="font-mono">{e.action}</span>
                        {Object.keys(e.detail ?? {}).length > 0 && (
                          <span className="ml-1.5 text-muted-foreground">{JSON.stringify(e.detail)}</span>
                        )}
                      </td>
                      <td className="py-1.5 pr-3 font-mono text-[10px] text-muted-foreground">{e.program_id ?? "—"}</td>
                      <td className={`py-1.5 font-mono ${e.status >= 400 ? "text-severity-critical" : "text-primary"}`}>{e.status}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
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
