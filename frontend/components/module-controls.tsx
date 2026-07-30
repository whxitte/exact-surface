"use client";

import { useEffect, useState } from "react";
import { Boxes, Lock, AlertTriangle, Info, ChevronDown } from "lucide-react";
import { api, type ModuleInfo } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { Switch } from "@/components/ui/switch";
import { cn } from "@/lib/utils";

/**
 * Which modules run for this program.
 *
 * The hard part isn't the toggle, it's honesty about consequences: modules form a
 * chain, so turning one off also stops everything downstream of it. The server
 * resolves that dependency graph and returns the real outcome, and this renders it —
 * before you save, and again afterwards on any module that won't run.
 */
export function ModuleControls({ programId }: { programId: string }) {
  const [modules, setModules] = useState<ModuleInfo[]>([]);
  const [busy, setBusy] = useState<string>("");
  const [error, setError] = useState("");
  const [isOpen, setIsOpen] = useState(false);

  function load() {
    api
      .getModules(programId)
      .then((r) => setModules(r.modules))
      .catch((e) => setError(e instanceof Error ? e.message : "could not load modules"));
  }
  useEffect(load, [programId]);

  async function toggle(mod: ModuleInfo, on: boolean) {
    setBusy(mod.name);
    setError("");
    try {
      // opt-in modules live in `enabled`; default-on ones are switched off via `disabled`
      const enabled = new Set(modules.filter((m) => m.opt_in && m.enabled).map((m) => m.name));
      const disabled = new Set(modules.filter((m) => m.turned_off).map((m) => m.name));
      if (mod.opt_in) {
        on ? enabled.add(mod.name) : enabled.delete(mod.name);
      } else {
        on ? disabled.delete(mod.name) : disabled.add(mod.name);
      }
      const res = await api.setModules(programId, [...enabled], [...disabled]);
      setModules(res.modules);
    } catch (e) {
      setError(e instanceof Error ? e.message : "could not update");
    } finally {
      setBusy("");
    }
  }

  if (modules.length === 0) return null;

  return (
    <Card>
      <CardContent className="p-5">
        <div
          onClick={() => setIsOpen(!isOpen)}
          className="flex items-center justify-between cursor-pointer select-none"
        >
          <div className="flex items-center gap-2">
            <Boxes className="h-4 w-4 text-primary" />
            <h2 className="text-sm font-semibold">Scan modules</h2>
          </div>
          <ChevronDown
            className={cn(
              "h-4 w-4 text-muted-foreground hover:text-foreground transition-transform duration-300",
              isOpen && "rotate-180"
            )}
          />
        </div>

        <div
          className="grid transition-[grid-template-rows] duration-300 ease-in-out"
          style={{ gridTemplateRows: isOpen ? "1fr" : "0fr" }}
        >
          <div className="overflow-hidden">
            <div className="space-y-4 pt-4">
              <p className="text-xs text-muted-foreground">
                Each module is a step an attacker would take. Turn one off and everything that
                depends on its output stops too — the warning under each switch says exactly what
                that costs.
              </p>

              <div className="space-y-1.5">
                {modules.map((m) => {
                  const costs = m.required_by.filter((d) =>
                    modules.some((x) => x.name === d && x.enabled),
                  );
                  return (
                    <div
                      key={m.name}
                      className={`rounded-md border p-3 ${
                        m.enabled ? "border-border" : "border-border/60 bg-muted/20"
                      }`}
                    >
                      <div className="flex items-start gap-3">
                        <div className="min-w-0 flex-1">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="text-sm font-medium">{m.label}</span>
                            {m.essential && (
                              <span
                                title="Everything downstream reads this module's output, so it cannot be turned off."
                                className="inline-flex items-center gap-1 rounded bg-muted px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-muted-foreground"
                              >
                                <Lock className="h-3 w-3" /> required
                              </span>
                            )}
                            {m.opt_in && !m.enabled && (
                              <span className="rounded bg-muted px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-muted-foreground">
                                off by default
                              </span>
                            )}
                          </div>
                          <p className="mt-0.5 text-xs text-muted-foreground">{m.summary}</p>

                          {/* Why it won't run — the server's resolved reason. */}
                          {!m.enabled && m.skip_reason && (
                            <p className="mt-1.5 flex items-start gap-1.5 text-xs text-severity-medium">
                              <Info className="mt-0.5 h-3 w-3 shrink-0" />
                              {m.skip_reason}
                            </p>
                          )}

                          {/* What switching it off would cost, while it is still on. */}
                          {m.enabled && !m.essential && costs.length > 0 && (
                            <p className="mt-1.5 flex items-start gap-1.5 text-xs text-muted-foreground">
                              <AlertTriangle className="mt-0.5 h-3 w-3 shrink-0 text-severity-medium" />
                              Turning this off also stops:{" "}
                              <span className="font-medium">
                                {costs
                                  .map((d) => modules.find((x) => x.name === d)?.label || d)
                                  .join(", ")}
                              </span>
                            </p>
                          )}
                        </div>

                        <div className="shrink-0 pt-0.5">
                          <Switch
                            checked={m.enabled}
                            disabled={m.essential || busy === m.name}
                            onChange={(on) => toggle(m, on)}
                            aria-label={`${m.enabled ? "Disable" : "Enable"} ${m.label}`}
                          />
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
              {error && <p className="text-sm text-severity-critical">{error}</p>}
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
