"use client";

import { useEffect, useState } from "react";
import { AlertTriangle, Clock } from "lucide-react";
import { api, type LicenseInfo } from "@/lib/api";

/**
 * Subscription banner. The API enforces read-only server-side (scans/new domains 402
 * when lapsed); this only explains *why* to the user and nudges renewal. Silent when
 * enforcement is off (self-serve/dev) or the subscription is healthy.
 */
export function LicenseBanner() {
  const [lic, setLic] = useState<LicenseInfo | null>(null);

  useEffect(() => {
    api.me().then((m) => setLic(m.license ?? null)).catch(() => {});
  }, []);

  if (!lic || !lic.enforced) return null;
  if (lic.status === "active" || lic.status === "unlicensed") return null;

  const renewBy = lic.grace_ends_at ? new Date(lic.grace_ends_at).toLocaleDateString() : null;

  if (lic.read_only) {
    return (
      <div className="flex items-start gap-3 border-b border-severity-critical/30 bg-severity-critical/10 px-4 py-2.5 text-sm sm:px-6 lg:px-8">
        <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-severity-critical" />
        <p className="text-severity-critical">
          <span className="font-semibold">Read-only mode.</span>{" "}
          {lic.reason} Scanning, 403-bypass and adding domains are paused; your existing findings
          stay viewable and exportable. Renew your subscription to resume.
        </p>
      </div>
    );
  }

  // grace: expired but still functional — nudge before it hardens to read-only.
  return (
    <div className="flex items-start gap-3 border-b border-severity-medium/30 bg-severity-medium/10 px-4 py-2.5 text-sm sm:px-6 lg:px-8">
      <Clock className="mt-0.5 h-4 w-4 shrink-0 text-severity-medium" />
      <p className="text-severity-medium">
        <span className="font-semibold">Subscription expired.</span> You&apos;re in the grace
        period{renewBy ? ` until ${renewBy}` : ""} — everything still works, but Vantari switches to
        read-only after that. Renew to avoid interruption.
      </p>
    </div>
  );
}
