"use client";

import { useEffect, useState } from "react";
import { Mail, Landmark, ShieldCheck, ShieldAlert } from "lucide-react";
import { api, type DomainIntel } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";

/**
 * Domain posture: can this domain be spoofed, and is the registration itself at risk.
 *
 * These are *state*, not events — "DMARC is none", "expires in 214 days" — so they read
 * badly as a list of findings and well as a panel. The matching Findings still exist for
 * alerting; this is the at-a-glance answer, with the raw records shown so the user can
 * verify rather than take our word for it.
 */
export function DomainIntelCard({ programId }: { programId: string }) {
  const [intel, setIntel] = useState<DomainIntel | null>(null);

  useEffect(() => {
    api.getDomainIntel(programId).then(setIntel).catch(() => {});
  }, [programId]);

  const email = intel?.email;
  const reg = intel?.registration;
  if (!email?.dmarc_present && !email?.spf_present && !reg?.registrar) return null;

  const spoofable = !!email?.spoofable;
  const days = reg?.days_to_expiry;
  const expirySoon = typeof days === "number" && days <= 90;

  return (
    <div className="grid gap-3 sm:grid-cols-2">
      {/* Email spoofability */}
      <Card className={spoofable ? "border-severity-high/40" : undefined}>
        <CardContent className="p-4">
          <div className="flex items-center gap-2">
            <Mail className="h-4 w-4 text-primary" />
            <h3 className="text-sm font-semibold">Email spoofing</h3>
            <span
              className={`ml-auto rounded-full px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide ${
                spoofable
                  ? "bg-severity-high/15 text-severity-high"
                  : "bg-severity-low/15 text-severity-low"
              }`}
            >
              {spoofable ? "spoofable" : "protected"}
            </span>
          </div>
          <p className="mt-1.5 text-xs text-muted-foreground">
            {spoofable
              ? "Anyone can send mail that appears to come from this domain — there is no enforcing DMARC policy to stop it."
              : "An enforcing DMARC policy is published, so forged mail from this domain is rejected."}
          </p>
          <dl className="mt-3 space-y-1.5 text-xs">
            <Row
              label="DMARC"
              value={email?.dmarc_policy ? `p=${email.dmarc_policy}` : "not published"}
              ok={email?.dmarc_policy === "reject" || email?.dmarc_policy === "quarantine"}
            />
            <Row label="SPF" value={email?.spf_present ? "published" : "not published"} ok={!!email?.spf_present} />
            <Row
              label="DKIM"
              value={
                email?.dkim_selectors?.length
                  ? email.dkim_selectors.join(", ")
                  : "no common selector found"
              }
              ok={!!email?.dkim_selectors?.length}
            />
          </dl>
          {/* The raw records, so the verdict above is checkable. */}
          {(email?.spf || email?.dmarc) && (
            <div className="mt-3 space-y-1 border-t border-border pt-2">
              {email?.spf && <Raw label="SPF" value={email.spf} />}
              {email?.dmarc && <Raw label="DMARC" value={email.dmarc} />}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Registration */}
      <Card className={expirySoon ? "border-severity-high/40" : undefined}>
        <CardContent className="p-4">
          <div className="flex items-center gap-2">
            <Landmark className="h-4 w-4 text-primary" />
            <h3 className="text-sm font-semibold">Domain registration</h3>
            {typeof days === "number" && (
              <span
                className={`ml-auto rounded-full px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide ${
                  days < 0
                    ? "bg-severity-critical/15 text-severity-critical"
                    : expirySoon
                      ? "bg-severity-high/15 text-severity-high"
                      : "bg-muted text-muted-foreground"
                }`}
              >
                {days < 0 ? "expired" : `${days}d left`}
              </span>
            )}
          </div>
          <dl className="mt-3 space-y-1.5 text-xs">
            <Row label="Registrar" value={reg?.registrar || "unknown"} />
            <Row label="Expires" value={reg?.expires_at ? reg.expires_at.slice(0, 10) : "unknown"} />
            <Row
              label="Transfer lock"
              value={reg?.transfer_locked ? "enabled" : "not set"}
              ok={!!reg?.transfer_locked}
            />
            <Row label="DNSSEC" value={reg?.dnssec ? "enabled" : "not enabled"} ok={!!reg?.dnssec} />
          </dl>
          {!!reg?.nameservers?.length && (
            <div className="mt-3 border-t border-border pt-2">
              <div className="text-[10px] uppercase tracking-wide text-muted-foreground">
                Nameservers
              </div>
              <div className="mt-1 flex flex-wrap gap-1">
                {reg.nameservers.map((ns) => (
                  <span key={ns} className="rounded bg-muted px-1.5 py-0.5 font-mono text-[10px]">
                    {ns}
                  </span>
                ))}
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function Row({ label, value, ok }: { label: string; value: string; ok?: boolean }) {
  return (
    <div className="flex items-center gap-2">
      <dt className="w-24 shrink-0 text-muted-foreground">{label}</dt>
      <dd className="flex min-w-0 items-center gap-1.5">
        {ok !== undefined &&
          (ok ? (
            <ShieldCheck className="h-3 w-3 shrink-0 text-severity-low" />
          ) : (
            <ShieldAlert className="h-3 w-3 shrink-0 text-severity-medium" />
          ))}
        <span className="truncate">{value}</span>
      </dd>
    </div>
  );
}

function Raw({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="text-[10px] uppercase tracking-wide text-muted-foreground">{label} record</div>
      <code className="block break-all font-mono text-[10px] text-muted-foreground">{value}</code>
    </div>
  );
}
