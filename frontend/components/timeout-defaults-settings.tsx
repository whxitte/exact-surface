"use client";

import { useEffect, useState } from "react";
import { Timer, Save } from "lucide-react";
import { api, type TimeoutDefaults } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { NumberInput } from "@/components/ui/number-input";
import { Select } from "@/components/ui/select";

type Unit = "s" | "m" | "h";
const UNIT_SECS: Record<Unit, number> = { s: 1, m: 60, h: 3600 };

function toParts(seconds: number): { value: number; unit: Unit } {
  if (seconds % 3600 === 0) return { value: seconds / 3600, unit: "h" };
  if (seconds % 60 === 0) return { value: seconds / 60, unit: "m" };
  return { value: seconds, unit: "s" };
}

export function TimeoutDefaultsSettings() {
  const [data, setData] = useState<TimeoutDefaults | null>(null);
  const [values, setValues] = useState<Record<string, number>>({});
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState("");

  function load() {
    api
      .getTimeoutDefaults()
      .then((d) => {
        setData(d);
        const seed: Record<string, number> = {};
        for (const s of d.stages)
          seed[s.stage] = d.timeout_overrides[s.stage] ?? s.default_seconds;
        setValues(seed);
      })
      .catch((e) => setMsg(e.message));
  }
  useEffect(load, []);

  async function save() {
    setSaving(true);
    setMsg("");
    try {
      const overrides: Record<string, number> = {};
      for (const s of data?.stages ?? [])
        if (values[s.stage] !== s.default_seconds) overrides[s.stage] = values[s.stage];
      const next = await api.setTimeoutDefaults(overrides);
      setData((prev) => (prev ? { ...prev, timeout_overrides: next.timeout_overrides } : prev));
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
          <Timer className="h-4 w-4 text-primary" />
          <h2 className="text-sm font-semibold">Phase time limits</h2>
        </div>
        <p className="text-xs text-muted-foreground">
          Max runtime per phase before it&apos;s stopped. The vulnerability scan (nuclei) is
          the slow one — bound it here. Tools that support it keep partial results at the
          limit. Applies to all domains; clamped to a safe range server-side.
        </p>

        <div className="grid gap-2 sm:grid-cols-2">
          {data.stages.map((s) => {
            const { value, unit } = toParts(values[s.stage] ?? s.default_seconds);
            const overridden =
              (data.timeout_overrides[s.stage] ?? s.default_seconds) !== s.default_seconds;
            return (
              <div
                key={s.stage}
                className="flex items-center gap-2 rounded-md border border-border px-3 py-2"
              >
                <span className="flex-1 text-sm">
                  {s.label}
                  {overridden && (
                    <span className="ml-2 rounded-full bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground">
                      custom
                    </span>
                  )}
                </span>
                <NumberInput
                  min={1}
                  value={value}
                  onChange={(val) =>
                    setValues((v) => ({
                      ...v,
                      [s.stage]: Math.max(1, val) * UNIT_SECS[unit],
                    }))
                  }
                />
                <Select
                  value={unit}
                  onChange={(e) =>
                    setValues((v) => ({ ...v, [s.stage]: value * UNIT_SECS[e.target.value as Unit] }))
                  }
                  className="h-8 w-16"
                >
                  <option value="s">sec</option>
                  <option value="m">min</option>
                  <option value="h">hr</option>
                </Select>
              </div>
            );
          })}
        </div>

        <div className="flex items-center gap-3">
          <Button onClick={save} disabled={saving}>
            <Save className="h-4 w-4" /> {saving ? "Saving…" : "Save time limits"}
          </Button>
          {msg && <span className="text-sm text-muted-foreground">{msg}</span>}
        </div>
      </CardContent>
    </Card>
  );
}
