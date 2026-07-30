"use client";

import { Suspense, useEffect, useRef, useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { CheckCircle2, XCircle } from "lucide-react";
import { ApiError, api } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { BrandLogo } from "@/components/brand-logo";

type State = "checking" | "ok" | "error";

function VerifyEmailInner() {
  const params = useSearchParams();
  const token = params.get("token");
  const [state, setState] = useState<State>("checking");
  const [message, setMessage] = useState("");
  const [resending, setResending] = useState(false);
  const [resendMsg, setResendMsg] = useState("");

  async function onResend() {
    setResending(true);
    setResendMsg("");
    try {
      await api.resendVerification();
      setResendMsg("Sent — check your inbox.");
    } catch (err) {
      // Resending needs a session; the link may have been opened in another browser.
      setResendMsg(
        err instanceof ApiError && err.status === 401
          ? "Sign in first, then request a new link."
          : err instanceof Error
            ? err.message
            : "could not resend",
      );
    } finally {
      setResending(false);
    }
  }
  // The token is one-time: React 18 StrictMode double-invokes effects in dev,
  // and a second call would consume-then-fail. Guard so we verify exactly once.
  const done = useRef(false);

  useEffect(() => {
    if (done.current) return;
    done.current = true;
    if (!token) {
      setState("error");
      setMessage("This link is missing its verification token.");
      return;
    }
    api
      .verifyEmail(token)
      .then((res) => {
        setState("ok");
        setMessage(res.email);
      })
      .catch((err) => {
        setState("error");
        setMessage(err instanceof Error ? err.message : "verification failed");
      });
  }, [token]);

  return (
    <div className="space-y-6">
      <div className="flex flex-col items-center gap-2 text-center">
        <BrandLogo className="h-12 w-12" size={96} />
        <h1 className="text-xl font-semibold tracking-tight">Email verification</h1>
      </div>

      <Card>
        <CardContent className="pt-5">
          {state === "checking" && (
            <p className="text-center text-sm text-muted-foreground">Verifying your email…</p>
          )}

          {state === "ok" && (
            <div className="flex flex-col items-center gap-3 text-center">
              <CheckCircle2 className="h-8 w-8 text-severity-low" />
              <p className="text-sm font-medium">Your email is verified.</p>
              {message && <p className="text-xs text-muted-foreground">{message}</p>}
            </div>
          )}

          {state === "error" && (
            <div className="flex flex-col items-center gap-3 text-center">
              <XCircle className="h-8 w-8 text-severity-critical" />
              <p className="text-sm font-medium">We couldn&apos;t verify this link.</p>
              <p className="text-xs text-muted-foreground">{message}</p>
              <p className="text-xs text-muted-foreground">
                Verification links are single-use and expire after 24 hours.
              </p>
              <Button variant="outline" size="sm" onClick={onResend} disabled={resending}>
                {resending ? "Sending…" : "Send me a new link"}
              </Button>
              {resendMsg && <p className="text-xs text-muted-foreground">{resendMsg}</p>}
            </div>
          )}
        </CardContent>
      </Card>

      <p className="text-center text-sm text-muted-foreground">
        <Link href="/login" className="text-primary hover:underline">
          Continue to sign in
        </Link>
      </p>
    </div>
  );
}

export default function VerifyEmailPage() {
  // useSearchParams requires a Suspense boundary for static prerendering.
  return (
    <Suspense fallback={<p className="text-center text-sm text-muted-foreground">Loading…</p>}>
      <VerifyEmailInner />
    </Suspense>
  );
}
