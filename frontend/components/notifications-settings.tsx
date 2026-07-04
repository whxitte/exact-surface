"use client";

import { useEffect, useState } from "react";
import { Bell, Trash2, Plus } from "lucide-react";
import { api, type Channel } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input, Label } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { SEVERITIES } from "@/lib/severity";

const TYPES = ["discord", "slack", "webhook", "telegram", "email"] as const;

function buildConfig(type: string, form: Record<string, string>): Record<string, string> {
  if (type === "discord" || type === "slack") return { webhook_url: form.webhook_url || "" };
  if (type === "webhook") return { url: form.webhook_url || "" };
  if (type === "telegram") return { bot_token: form.bot_token || "", chat_id: form.chat_id || "" };
  if (type === "email") return { to: form.to || "" };
  return {};
}

export function NotificationsSettings() {
  const [channels, setChannels] = useState<Channel[]>([]);
  const [name, setName] = useState("");
  const [type, setType] = useState<string>("discord");
  const [minSev, setMinSev] = useState("medium");
  const [form, setForm] = useState<Record<string, string>>({});
  const [error, setError] = useState("");

  function load() {
    api.listChannels().then(setChannels).catch((e) => setError(e.message));
  }
  useEffect(load, []);

  async function addChannel(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    try {
      await api.createChannel({
        name: name.trim(),
        type,
        min_severity: minSev,
        config: buildConfig(type, form),
      });
      setName("");
      setForm({});
      load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "failed");
    }
  }

  async function remove(id: string) {
    await api.deleteChannel(id);
    load();
  }

  const webhookLike = type === "discord" || type === "slack" || type === "webhook";

  return (
    <Card>
      <CardContent className="space-y-4 p-5">
        <div className="flex items-center gap-2">
          <Bell className="h-4 w-4 text-primary" />
          <h2 className="text-sm font-semibold">Notification channels</h2>
        </div>

        {channels.length > 0 && (
          <div className="space-y-2">
            {channels.map((c) => (
              <div
                key={c.channel_id}
                className="flex items-center gap-3 rounded-md border border-border px-3 py-2 text-sm"
              >
                <span className="rounded-full bg-muted px-2 py-0.5 text-xs capitalize">{c.type}</span>
                <span className="flex-1 font-medium">{c.name}</span>
                <span className="text-xs text-muted-foreground">≥ {c.min_severity}</span>
                <button onClick={() => remove(c.channel_id)} className="text-muted-foreground hover:text-severity-critical">
                  <Trash2 className="h-4 w-4" />
                </button>
              </div>
            ))}
          </div>
        )}

        <form onSubmit={addChannel} className="grid grid-cols-2 gap-3">
          <div className="space-y-1.5">
            <Label>Name</Label>
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="ops-alerts" required />
          </div>
          <div className="space-y-1.5">
            <Label>Type</Label>
            <Select value={type} onChange={(e) => setType(e.target.value)}>
              {TYPES.map((t) => (
                <option key={t} value={t}>{t}</option>
              ))}
            </Select>
          </div>

          {webhookLike && (
            <div className="col-span-2 space-y-1.5">
              <Label>Webhook URL</Label>
              <Input
                value={form.webhook_url || ""}
                onChange={(e) => setForm({ ...form, webhook_url: e.target.value })}
                placeholder="https://…"
                required
              />
            </div>
          )}
          {type === "telegram" && (
            <>
              <div className="space-y-1.5">
                <Label>Bot token</Label>
                <Input value={form.bot_token || ""} onChange={(e) => setForm({ ...form, bot_token: e.target.value })} required />
              </div>
              <div className="space-y-1.5">
                <Label>Chat ID</Label>
                <Input value={form.chat_id || ""} onChange={(e) => setForm({ ...form, chat_id: e.target.value })} required />
              </div>
            </>
          )}
          {type === "email" && (
            <div className="col-span-2 space-y-1.5">
              <Label>Recipient</Label>
              <Input value={form.to || ""} onChange={(e) => setForm({ ...form, to: e.target.value })} placeholder="soc@company.com" required />
            </div>
          )}

          <div className="space-y-1.5">
            <Label>Min severity</Label>
            <Select value={minSev} onChange={(e) => setMinSev(e.target.value)}>
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>{s}</option>
              ))}
            </Select>
          </div>
          <div className="flex items-end">
            <Button type="submit" className="w-full">
              <Plus className="h-4 w-4" /> Add channel
            </Button>
          </div>
        </form>
        {error && <p className="text-sm text-severity-critical">{error}</p>}
      </CardContent>
    </Card>
  );
}
