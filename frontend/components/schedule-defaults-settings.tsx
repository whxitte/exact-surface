"use client";

import { useEffect, useState } from "react";
import { CalendarClock, Save } from "lucide-react";
import { api, type ScheduleDefaults } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";

type Unit = "m" | "h" | "d";
const UNIT_SECS: Record<Unit, number> = { m: 60, h: 3600, d: 86400 };

function toParts(seconds: number): { value: number; unit: Unit } {
  if (seconds % 86400 === 0) return { value: seconds / 86400, unit: "d" };
  if (seconds % 3600 === 0) return { value: seconds / 3600, unit: "h" };
  return { value: Math.max(1, Math.round(seconds / 60)), unit: "m" };
}

export function ScheduleDefaultsSettings() {
  const [data, setData] = useState<ScheduleDefaults | null>(null);
  const [values, setValues] = useState<Record<string, number>>({});
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState("");

  function load() {
    api
      .getScheduleDefaults()
      .then((d) => {
        setData(d);
        const seed: Record<string, number> = {};
        for (const p of d.pipelines)
          seed[p.pipeline] = d.cadence_overrides[p.pipeline] ?? p.default_seconds;
        setValues(seed);
      })
      .catch((e) => setMsg(e.message));
  }
  useEffect(load, []);

  async function save() {
    setSaving(true);
    setMsg("");
    try {
      // only send values that differ from the built-in default → real overrides
      const overrides: Record<string, number> = {};
      for (const p of data?.pipelines ?? [])
        if (values[p.pipeline] !== p.default_seconds) overrides[p.pipeline] = values[p.pipeline];
      const next = await api.setScheduleDefaults(overrides);
      setData((prev) => (prev ? { ...prev, cadence_overrides: next.cadence_overrides } : prev));
      setMsg("Saved.");
    } catch (e) {
      setMsg(e instanceof Error ? e.message : "failed");
    } finally {
      setSaving(false);
    }
  }

  if (!data) return null;

  return (
    <Card>
      <CardContent className="space-y-4 p-5">
        <div className="flex items-center gap-2">
          <CalendarClock className="h-4 w-4 text-primary" />
          <h2 className="text-sm font-semibold">Default scan schedule</h2>
        </div>
        <p className="text-xs text-muted-foreground">
          How often each phase re-runs, for all domains. A domain can override these on its
          own page. Values below the safety floor are clamped server-side.
        </p>

        <div className="grid gap-2 sm:grid-cols-2">
          {data.pipelines.map((p) => {
            const { value, unit } = toParts(values[p.pipeline] ?? p.default_seconds);
            const overridden = (data.cadence_overrides[p.pipeline] ?? p.default_seconds) !== p.default_seconds;
            return (
              <div
                key={p.pipeline}
                className="flex items-center gap-2 rounded-md border border-border px-3 py-2"
              >
                <span className="flex-1 text-sm">
                  {p.label}
                  {overridden && (
                    <span className="ml-2 rounded-full bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground">
                      custom
                    </span>
                  )}
                </span>
                <Input
                  type="number"
                  min={1}
                  value={value}
                  onChange={(e) =>
                    setValues((v) => ({
                      ...v,
                      [p.pipeline]: Math.max(1, Number(e.target.value)) * UNIT_SECS[unit],
                    }))
                  }
                  className="h-8 w-16"
                />
                <Select
                  value={unit}
                  onChange={(e) =>
                    setValues((v) => ({ ...v, [p.pipeline]: value * UNIT_SECS[e.target.value as Unit] }))
                  }
                  className="h-8 w-16"
                >
                  <option value="m">min</option>
                  <option value="h">hr</option>
                  <option value="d">day</option>
                </Select>
              </div>
            );
          })}
        </div>

        <div className="flex items-center gap-3">
          <Button onClick={save} disabled={saving}>
            <Save className="h-4 w-4" /> {saving ? "Saving…" : "Save defaults"}
          </Button>
          {msg && <span className="text-sm text-muted-foreground">{msg}</span>}
        </div>
      </CardContent>
    </Card>
  );
}
