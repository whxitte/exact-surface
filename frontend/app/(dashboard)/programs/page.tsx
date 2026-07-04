"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Globe, Plus, CheckCircle2, AlertCircle, ChevronRight } from "lucide-react";
import { api, type Program } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

export default function ProgramsPage() {
  const [programs, setPrograms] = useState<Program[]>([]);
  const [apex, setApex] = useState("");
  const [error, setError] = useState("");
  const [adding, setAdding] = useState(false);

  function load() {
    api.listPrograms().then(setPrograms).catch((e) => setError(e.message));
  }
  useEffect(load, []);

  async function addProgram(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setAdding(true);
    try {
      await api.createProgram(apex.trim());
      setApex("");
      load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "failed to add");
    } finally {
      setAdding(false);
    }
  }

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Programs</h1>
        <p className="text-sm text-muted-foreground">Domains Vantari is watching for you.</p>
      </div>

      <Card>
        <CardContent className="p-5">
          <form onSubmit={addProgram} className="flex items-end gap-3">
            <div className="flex-1">
              <label className="mb-1.5 block text-sm font-medium text-muted-foreground">
                Add a domain
              </label>
              <Input value={apex} onChange={(e) => setApex(e.target.value)}
                placeholder="your-company.com" required />
            </div>
            <Button type="submit" disabled={adding}>
              <Plus className="h-4 w-4" />
              {adding ? "Adding…" : "Add domain"}
            </Button>
          </form>
          {error && <p className="mt-3 text-sm text-severity-critical">{error}</p>}
        </CardContent>
      </Card>

      <div className="space-y-2">
        {programs.length === 0 && (
          <p className="py-8 text-center text-sm text-muted-foreground">
            No programs yet. Add your first domain above.
          </p>
        )}
        {programs.map((p) => (
          <Link key={p.program_id} href={`/programs/${p.program_id}`}>
            <Card className="transition-colors hover:border-primary/40">
              <CardContent className="flex items-center gap-4 p-4">
                <div className="flex h-9 w-9 items-center justify-center rounded-md bg-muted text-muted-foreground">
                  <Globe className="h-4 w-4" />
                </div>
                <div className="flex-1">
                  <div className="font-medium">{p.apex_domain}</div>
                  <div className="text-xs text-muted-foreground">{p.program_id}</div>
                </div>
                {p.verified ? (
                  <span className="flex items-center gap-1.5 text-xs text-primary">
                    <CheckCircle2 className="h-4 w-4" /> Verified
                  </span>
                ) : (
                  <span className="flex items-center gap-1.5 text-xs text-severity-medium">
                    <AlertCircle className="h-4 w-4" /> Unverified
                  </span>
                )}
                <ChevronRight className="h-4 w-4 text-muted-foreground" />
              </CardContent>
            </Card>
          </Link>
        ))}
      </div>
    </div>
  );
}
