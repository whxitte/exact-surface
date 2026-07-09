"use client";

import { useEffect, useState } from "react";
import { KeyRound, Check, Trash2 } from "lucide-react";
import { api, type Integration } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input, Label } from "@/components/ui/input";

function IntegrationRow({ item, onChanged }: { item: Integration; onChanged: () => void }) {
  const [value, setValue] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function save() {
    if (!value.trim()) return;
    setBusy(true);
    setError("");
    try {
      await api.setIntegration(item.name, value.trim());
      setValue("");
      onChanged();
    } catch (err) {
      setError(err instanceof Error ? err.message : "failed");
    } finally {
      setBusy(false);
    }
  }

  async function clear() {
    setBusy(true);
    try {
      await api.clearIntegration(item.name);
      onChanged();
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-1.5 rounded-md border border-border p-3">
      <div className="flex items-center gap-2">
        <Label className="flex-1">{item.label}</Label>
        {item.configured && (
          <span className="flex items-center gap-1 text-xs text-severity-low">
            <Check className="h-3.5 w-3.5" /> {item.masked || "set"}
          </span>
        )}
      </div>
      <p className="text-xs text-muted-foreground">{item.help}</p>
      <div className="flex gap-2">
        <Input
          type={item.secret ? "password" : "text"}
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder={item.configured ? "Replace value…" : "Enter value…"}
          onKeyDown={(e) => e.key === "Enter" && save()}
        />
        <Button onClick={save} disabled={busy || !value.trim()} className="shrink-0">
          Save
        </Button>
        {item.configured && (
          <button
            onClick={clear}
            disabled={busy}
            className="shrink-0 px-2 text-muted-foreground hover:text-severity-critical"
            title="Clear"
          >
            <Trash2 className="h-4 w-4" />
          </button>
        )}
      </div>
      {error && <p className="text-xs text-severity-critical">{error}</p>}
    </div>
  );
}

export function IntegrationsSettings() {
  const [items, setItems] = useState<Integration[]>([]);
  const [error, setError] = useState("");

  function load() {
    api.listIntegrations().then(setItems).catch((e) => setError(e.message));
  }
  useEffect(load, []);

  return (
    <Card>
      <CardContent className="space-y-4 p-5">
        <div className="flex items-center gap-2">
          <KeyRound className="h-4 w-4 text-primary" />
          <h2 className="text-sm font-semibold">Integrations &amp; API keys</h2>
        </div>
        <p className="text-xs text-muted-foreground">
          Keys are stored encrypted and never shown again after saving. A key set here
          unlocks its module (e.g. a GitHub token enables leaked-secret OSINT).
        </p>

        <div className="space-y-3">
          {items.map((item) => (
            <IntegrationRow key={item.name} item={item} onChanged={load} />
          ))}
        </div>
        {error && <p className="text-sm text-severity-critical">{error}</p>}
      </CardContent>
    </Card>
  );
}
