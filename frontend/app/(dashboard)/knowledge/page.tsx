"use client";

import { useMemo, useState } from "react";
import {
  BookOpen, Search, Workflow, Radar, RefreshCw, Activity, ShieldAlert, KeyRound,
  GitBranch, Bug, Network, BellRing, Lock, Plug, HelpCircle,
} from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";

interface Section {
  id: string;
  title: string;
  icon: React.ComponentType<{ className?: string }>;
  keywords: string;
  body: React.ReactNode;
}

function Term({ children }: { children: React.ReactNode }) {
  return <span className="font-medium text-foreground">{children}</span>;
}
function Code({ children }: { children: React.ReactNode }) {
  return (
    <code className="rounded bg-muted px-1 py-0.5 font-mono text-[0.85em] text-foreground">
      {children}
    </code>
  );
}
function Q({ q, children }: { q: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="font-medium text-foreground">{q}</div>
      <div className="mt-1 text-muted-foreground">{children}</div>
    </div>
  );
}

const SECTIONS: Section[] = [
  {
    id: "what",
    title: "What Vantari is",
    icon: Radar,
    keywords: "overview easm attack surface external what is vantari",
    body: (
      <>
        <p>
          Vantari is a continuous <Term>External Attack Surface Management (EASM)</Term> platform.
          You add a domain you own; Vantari discovers everything that domain exposes to the internet
          — subdomains, live hosts, open ports, services, endpoints, technologies, secrets, and
          vulnerabilities — and then keeps watching it so you learn the moment something changes.
        </p>
        <p>
          It is a <Term>detection-only</Term> tool. It maps and monitors what an attacker would see;
          it never exploits, alters, or takes down anything it finds.
        </p>
      </>
    ),
  },
  {
    id: "pipeline",
    title: "The scan pipeline (attacker's-eye view)",
    icon: Workflow,
    keywords: "pipeline stages phases kill chain modules subfinder httpx naabu nuclei crawl",
    body: (
      <>
        <p>
          A full scan runs an ordered pipeline that mirrors an attacker&apos;s recon workflow. Each
          stage feeds the next:
        </p>
        <ol className="ml-4 list-decimal space-y-1.5">
          <li><Term>Ingest</Term> — enumerate subdomains (subfinder, crt.sh, DNS).</li>
          <li>
            <Term>Uncover</Term> — passive host discovery from Shodan/Censys (optional; needs
            an API key). Off by default.
          </li>
          <li><Term>Probe</Term> — which hosts are alive over HTTP/S, their status, title, tech (httpx).</li>
          <li><Term>TLS</Term> — certificate chain, expiry, SANs (tlsx).</li>
          <li><Term>Takeover</Term> — dangling DNS / claimable cloud services (see below).</li>
          <li><Term>Crawl</Term> — walk each live site for links and endpoints (katana, gau, wayback).</li>
          <li><Term>Content discovery</Term> — brute-force hidden paths/files (feroxbuster).</li>
          <li><Term>Port scan</Term> — open ports on confirmed-dedicated infrastructure (naabu).</li>
          <li><Term>Service scan</Term> — identify the service/version on each port (nmap).</li>
          <li><Term>Vulnerability scan</Term> — templated checks against every host (nuclei).</li>
          <li><Term>Secrets</Term> — fetch JS/config bodies and scan for exposed keys (regex + trufflehog).</li>
          <li><Term>CVE watch</Term> — match detected tech/versions against the NVD + CISA KEV feeds.</li>
          <li><Term>GitHub OSINT</Term> — search public code for leaked credentials referencing your domain.</li>
          <li><Term>Dork</Term> — search-engine dorks for indexed exposures.</li>
          <li><Term>Correlate</Term> — rank hosts by combined risk (the Priorities tab).</li>
          <li><Term>Notify</Term> — deliver new findings to your channels per your alert policy.</li>
        </ol>
        <p>
          You can see each stage run live under <Term>Activity</Term>, and set its cadence and timeout
          under a program&apos;s <Term>schedule</Term> settings.
        </p>
        <p className="rounded-md border border-border bg-muted/30 p-3 text-muted-foreground">
          <Term>Optional modules</Term> — Uncover, TLS, Service-ID, and Dorking are off by default
          and only run inside a <Term>full</Term> pipeline scan (first add, or a manual scan), not on
          the continuous per-phase schedule. Enable them per program under its Optional modules, then
          trigger a scan to see them run.
        </p>
      </>
    ),
  },
  {
    id: "continuous",
    title: "Continuous monitoring & cascade",
    icon: RefreshCw,
    keywords: "continuous monitoring cadence schedule cascade first scan baseline new subdomain",
    body: (
      <>
        <p>
          The <Term>first</Term> scan of a program is a single ordered full run — it establishes your
          baseline. After it completes, Vantari switches to <Term>continuous</Term> mode: each phase
          re-runs on its own cadence (e.g. CVE watch every 15 min, subdomain enumeration every 6 h,
          full nuclei every 12 h). You configure these per program or account-wide in Settings.
        </p>
        <p>
          On top of the schedule there is an <Term>event-driven cascade</Term>: when re-enumeration
          finds a brand-new subdomain, Vantari immediately runs the downstream phases (probe, crawl,
          scan…) for just that host, instead of waiting for the next full cycle. A cascade run is
          <Term> target-scoped</Term> — it only covers the new hosts.
        </p>
      </>
    ),
  },
  {
    id: "live-gone",
    title: "Live vs. Gone / Resolved — how we decide",
    icon: Activity,
    keywords: "gone resolved live stale removed closed false positive accuracy evidence last seen",
    body: (
      <>
        <p>
          A core promise is showing <Term>what is live right now</Term>. Every asset, endpoint, port,
          finding, and CVE is kept with a history (first-seen / last-seen), and marked <Term>gone</Term>
          {" "}(assets/endpoints/ports) or <Term>resolved</Term> (findings/CVEs) when it is no longer
          present.
        </p>
        <p>
          Crucially, gone is <Term>evidence-based, never time-based</Term>. An item is only marked gone
          when a <Term>full-coverage re-run of its own producing phase</Term> re-scanned its target and
          did not re-observe it. Concretely:
        </p>
        <ul className="ml-4 list-disc space-y-1.5">
          <li>
            Each item is judged only against its own phase — a hidden path found by content-discovery is
            compared to the next content-discovery run, never to a quick probe that only re-checks home
            pages.
          </li>
          <li>
            <Term>Cascade (target-scoped) runs are ignored</Term> as evidence — they only cover a few new
            hosts, so they can&apos;t prove anything about the rest.
          </li>
          <li>
            If a re-run <Term>fails or finds nothing</Term> (a flaky tool, a network blip), no item is
            marked gone — we wait for a clean run rather than wrongly resolving live assets.
          </li>
          <li>
            When a gone item is seen again, it <Term>automatically returns</Term> to live on the next scan.
          </li>
        </ul>
        <p className="rounded-md border border-border bg-muted/30 p-3 text-muted-foreground">
          <Term>Why gone may not appear immediately:</Term> it needs a <em>second</em> full-coverage run
          of that phase. After the initial baseline, everything is &quot;live&quot;; the first resolutions
          appear once that phase runs again and misses something. Gone items are dimmed and hidden behind a
          &quot;show gone&quot; toggle, and also listed on the <Term>Changes</Term> page — never deleted, so
          you can always verify.
        </p>
      </>
    ),
  },
  {
    id: "findings",
    title: "Findings, severity & confirmation",
    icon: ShieldAlert,
    keywords: "findings nuclei severity confirmed unconfirmed resolved detected tech wappalyzer curl request actionable informational false positive fp rate triage",
    body: (
      <>
        <p>
          Findings come from several modules (shown as a tag): <Code>nuclei</Code> (templated vuln
          checks), <Code>tlsx</Code> (cert issues), <Code>takeover</Code>, and <Code>dork</Code>. Open
          any finding to expand full detail — description, the exact match, detected technology,
          references, and the raw cURL / request / response so you can reproduce it.
        </p>
        <p>
          Severity is info → critical. A finding marked <Term>resolved</Term> is one a full re-run of its
          module no longer reports (see Live vs. Gone). Dork results also land here, tagged <Code>dork</Code>.
        </p>
        <p>
          <Term>Actionable vs. informational.</Term> A scan surfaces a lot of inventory — tech
          fingerprints, TLS version, missing headers, CAA records. Those are <Term>informational</Term>{" "}
          (info/low). The Overview leads with <Term>Actionable</Term> — findings that are still open and{" "}
          <Term>medium</Term> or above — so triage isn&apos;t buried. Notifications use the same floor by
          default (your alert policy).
        </p>
        <p>
          <Term>False-positive rate.</Term> When you mark a finding <Term>false positive</Term> (or
          confirm/accept/resolve it), it counts toward the <Term>FP rate</Term> shown on the Overview —
          false positives ÷ findings you&apos;ve decided. A low rate (target under 5%) is what keeps the
          signal trustworthy; it reads &quot;—&quot; until you&apos;ve triaged your first finding.
        </p>
      </>
    ),
  },
  {
    id: "takeover",
    title: "Subdomain takeover detection",
    icon: Bug,
    keywords: "takeover s3 cloudfront nosuchbucket cname dangling nxdomain github pages heroku azure",
    body: (
      <>
        <p>
          A <Term>subdomain takeover</Term> happens when a subdomain points at a cloud service that has
          been de-provisioned — an attacker can re-claim that service and serve content from your
          subdomain. Vantari detects two signals:
        </p>
        <ul className="ml-4 list-disc space-y-1.5">
          <li><Term>Dangling CNAME</Term> — the record points at a claimable service that no longer resolves.</li>
          <li>
            <Term>HTTP fingerprint</Term> — the page returns a known &quot;unclaimed&quot; body (e.g. S3&apos;s
            <Code>NoSuchBucket</Code>, GitHub Pages&apos; &quot;There isn&apos;t a GitHub Pages site here&quot;).
          </li>
        </ul>
        <p>
          The body is scanned against every known service <em>regardless of the CNAME</em> — important
          for S3 fronted by CloudFront, where the CNAME is <Code>*.cloudfront.net</Code> but the body is
          S3&apos;s error. Confirmed risks appear on the <Term>DNS</Term> page and as HIGH findings.
        </p>
      </>
    ),
  },
  {
    id: "secrets",
    title: "Secrets & public leaks",
    icon: KeyRound,
    keywords: "secrets trufflehog regex leaks github token verified masked plaintext spa index html",
    body: (
      <>
        <p>
          <Term>Secrets</Term> are keys/tokens exposed in your own assets (JS, config, .env files). Two
          engines run over each fetched body: a fast always-on regex detector, plus <Code>trufflehog</Code>
          {" "}(800+ detectors with live <Term>verification</Term> — a verified hit is a key that works
          right now). Vantari stores only a <Term>masked</Term> value and a keyed hash — never the plaintext.
        </p>
        <p>
          <Term>Leaks</Term> (the Leaks tab) are your credentials found in <em>public</em> GitHub code.
          This needs a GitHub token in Settings → Integrations.
        </p>
        <p className="rounded-md border border-border bg-muted/30 p-3 text-muted-foreground">
          <Term>Why a big site can show 0 secrets:</Term> single-page apps serve the same
          <Code>index.html</Code> for thousands of discovered paths, so most fetched bodies contain no
          secret. The scan logs show how many fetches returned real text vs. the SPA shell.
        </p>
      </>
    ),
  },
  {
    id: "cves",
    title: "CVEs",
    icon: Bug,
    keywords: "cve kev nvd cvss confidence tech version match",
    body: (
      <p>
        The CVE watch matches the technology + versions detected on your hosts against the NVD feed and
        the CISA <Term>Known-Exploited-Vulnerabilities (KEV)</Term> catalogue. Each match shows a
        confidence (how sure the tech/version fingerprint is), CVSS, and a KEV badge when it&apos;s
        actively exploited in the wild. Matches link out to the NVD detail page.
      </p>
    ),
  },
  {
    id: "ports",
    title: "Ports & severity",
    icon: Network,
    keywords: "ports naabu service product severity reason dns http database critical",
    body: (
      <p>
        The Ports tab lists every open port with its service/product and a derived severity + reason.
        Ports carry no severity from the scanner, so Vantari grades by exposure: a directly-reachable
        database/cache (MySQL, Redis, MongoDB, Elasticsearch…) is <Term>critical</Term>; remote-admin
        (SSH, RDP, SMB) is <Term>high</Term>; web/DNS is informational. Port scanning only runs on
        infrastructure confirmed to be dedicated to you (shared cloud IPs are HTTP-checked only).
      </p>
    ),
  },
  {
    id: "alerts",
    title: "Alert policy",
    icon: BellRing,
    keywords: "alert policy notifications severity floor new subdomain port filter channels",
    body: (
      <>
        <p>
          You decide what actually pages you, resolved as built-ins ← account defaults ← per-program
          (most specific wins). You can set a minimum severity floor, toggle each family (findings /
          secrets / leaks / CVEs), require a CVSS floor for CVEs, and opt into change events:
        </p>
        <ul className="ml-4 list-disc space-y-1.5">
          <li><Term>New subdomain</Term> appears, and/or a <Term>new open port</Term> opens.</li>
          <li>Port events can be filtered with an nmap-style spec (<Code>22,80,443</Code> or <Code>1-1024</Code>).</li>
        </ul>
        <p className="rounded-md border border-border bg-muted/30 p-3 text-muted-foreground">
          Change-event alerts only fire <Term>after the baseline scan</Term>, so the first enumeration
          doesn&apos;t page you for every subdomain it finds. They alert only on things that appear
          afterwards.
        </p>
      </>
    ),
  },
  {
    id: "scope",
    title: "Scope & safety",
    icon: Lock,
    keywords: "scope safety authorization verification dedicated shared cidr consent politeness",
    body: (
      <p>
        Before any active scanning, you must <Term>verify ownership</Term> of the domain (DNS/HTTP token)
        and grant <Term>authorization</Term>. A central scope engine then gates every action: shared
        cloud/CDN IPs get HTTP-only checks, only infrastructure confirmed as dedicated to you is
        port-scanned or actively probed, and a hard deny-list is never overridable. Scanning is
        rate-limited for politeness.
      </p>
    ),
  },
  {
    id: "integrations",
    title: "Integrations & configuration",
    icon: Plug,
    keywords: "integrations github token google cse shodan censys uncover brave dork api key settings",
    body: (
      <>
        <p>Set these in <Term>Settings → Integrations</Term> (stored encrypted, per tenant). Every
          integration degrades gracefully — the module skips, it never fails the scan:</p>
        <ul className="ml-4 list-disc space-y-1.5">
          <li>
            <Term>GitHub token</Term> — required for the Leaks / GitHub-OSINT module. Without it, the
            module skips.
          </li>
          <li>
            <Term>Google CSE key + CX</Term> — enables dorking. Create a Programmable Search Engine (for
            the <Code>cx</Code>) and enable the &quot;Custom Search API&quot; in Google Cloud (for the key).
            The JSON API is free up to 100 queries/day and is not deprecated.
          </li>
          <li>
            <Term>Shodan API key</Term> and/or <Term>Censys API ID + Secret</Term> — enable the Uncover
            module (passive host discovery). Note: Shodan&apos;s <em>search</em> requires a paid
            membership (a free key can&apos;t run searches and returns nothing); Censys has a free search
            tier. If a key is present but empty results come back, the scan log shows the reason.
          </li>
        </ul>
      </>
    ),
  },
  {
    id: "faq",
    title: "FAQ & caveats",
    icon: HelpCircle,
    keywords: "faq caveats questions why zero secrets gone false positive two scans flaky",
    body: (
      <div className="space-y-3">
        <Q q="Why does gone/resolved sometimes lag?">
          It is intentional. Gone requires <Term>proof</Term> — a full-coverage re-run of that phase that
          missed the item. That means at least two full-coverage runs before anything resolves. Accuracy
          over recency.
        </Q>
        <Q q="Can a live item be wrongly marked gone?">
          Very unlikely by design: cascade runs are ignored, and a re-run that observed nothing marks
          nothing gone. The only residual case is a scanner that partially fails (re-finds some items but
          genuinely misses a live one); that self-corrects on the next clean run, and nothing is ever
          deleted — you can verify from the dimmed / &quot;show gone&quot; view.
        </Q>
        <Q q="Findings show 0 secrets — is the scanner broken?">
          Usually no. Most modern sites are single-page apps that return the same HTML shell for every
          path, so there is nothing to find. The scan logs report how many fetched bodies were real text.
        </Q>
        <Q q="Where do dork results appear?">
          In the <Term>Findings</Term> tab, tagged <Code>dork</Code>. Dorking is skipped unless a Google
          CSE key is configured.
        </Q>
        <Q q="Does Vantari ever attack or change my systems?">
          No. It is detection-only: it observes, fingerprints, and reports. It never exploits, writes, or
          disrupts.
        </Q>
      </div>
    ),
  },
];

export default function KnowledgePage() {
  const [q, setQ] = useState("");
  const [active, setActive] = useState<string>(SECTIONS[0].id);

  const shown = useMemo(() => {
    const needle = q.trim().toLowerCase();
    if (!needle) return SECTIONS;
    return SECTIONS.filter(
      (s) => s.title.toLowerCase().includes(needle) || s.keywords.includes(needle),
    );
  }, [q]);

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-semibold tracking-tight">
            <BookOpen className="h-6 w-6 text-primary" /> Knowledge
          </h1>
          <p className="text-sm text-muted-foreground">
            How Vantari works, what each signal means, and the conditions behind it.
          </p>
        </div>
        <div className="relative">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search the docs…"
            className="h-9 w-64 rounded-full border border-border bg-background pl-9 pr-3 text-sm focus:border-primary focus:outline-none"
          />
        </div>
      </div>

      <div className="flex gap-6">
        {/* in-page nav */}
        <nav className="sticky top-6 hidden h-fit w-56 shrink-0 space-y-1 lg:block">
          {shown.map((s) => (
            <a
              key={s.id}
              href={`#${s.id}`}
              onClick={() => setActive(s.id)}
              className={cn(
                "flex items-center gap-2 rounded-md px-3 py-1.5 text-sm transition-colors",
                active === s.id
                  ? "bg-primary/10 text-primary"
                  : "text-muted-foreground hover:text-foreground",
              )}
            >
              <s.icon className="h-4 w-4 shrink-0" />
              <span className="truncate">{s.title}</span>
            </a>
          ))}
        </nav>

        <div className="min-w-0 flex-1 space-y-4">
          {shown.length === 0 && (
            <p className="py-8 text-center text-sm text-muted-foreground">Nothing matches “{q}”.</p>
          )}
          {shown.map((s) => (
            <Card key={s.id} id={s.id} className="scroll-mt-6">
              <CardContent className="space-y-3 p-5 text-sm leading-relaxed">
                <h2 className="flex items-center gap-2 text-base font-semibold">
                  <s.icon className="h-4 w-4 text-primary" /> {s.title}
                </h2>
                <div className="space-y-3 text-muted-foreground [&_p]:leading-relaxed">{s.body}</div>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    </div>
  );
}
