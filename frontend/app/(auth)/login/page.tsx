"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { api } from "@/lib/api";
import { setSession } from "@/lib/auth";
import { Button } from "@/components/ui/button";
import { Input, Label } from "@/components/ui/input";
import { Card, CardContent } from "@/components/ui/card";
import { BrandLogo } from "@/components/brand-logo";

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  // Self-hosted instances serve one organisation: signup closes after the first
  // account. Defaults to hidden rather than shown-then-yanked, so the common case
  // (an already-set-up instance) never flashes a link that would 403 on submit.
  const [signupOpen, setSignupOpen] = useState(false);

  useEffect(() => {
    api
      .signupOpen()
      .then((r) => setSignupOpen(r.open))
      .catch(() => {}); // instance state is unknown; stay hidden rather than guess
  }, []);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const res = await api.login(email, password);
      setSession(res.access_token, res.tenant_id);
      router.push("/overview");
    } catch (err) {
      setError(err instanceof Error ? err.message : "login failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col items-center gap-2 text-center">
        <BrandLogo className="h-12 w-12" size={96} />
        <h1 className="text-xl font-semibold tracking-tight">Sign in to ExactSurface</h1>
        <p className="text-sm text-muted-foreground">Continuous attack-surface intelligence</p>
      </div>

      <Card>
        <CardContent className="pt-5">
          <form onSubmit={onSubmit} className="space-y-4">
            <div className="space-y-1.5">
              <Label htmlFor="email">Email</Label>
              <Input id="email" type="email" value={email} required
                onChange={(e) => setEmail(e.target.value)} placeholder="you@company.com" />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="password">Password</Label>
              <Input id="password" type="password" value={password} required
                onChange={(e) => setPassword(e.target.value)} placeholder="••••••••" />
            </div>
            {error && <p className="text-sm text-severity-critical">{error}</p>}
            <Button type="submit" className="w-full" disabled={loading}>
              {loading ? "Signing in…" : "Sign in"}
            </Button>
          </form>
        </CardContent>
      </Card>

      {signupOpen && (
        <p className="text-center text-sm text-muted-foreground">
          No account?{" "}
          <Link href="/signup" className="text-primary hover:underline">
            Create one
          </Link>
        </p>
      )}
    </div>
  );
}
