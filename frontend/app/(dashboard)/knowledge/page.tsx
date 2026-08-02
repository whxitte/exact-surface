"use client";

import { useMemo, useState } from "react";
import {
  BookOpen, Search, Workflow, Radar, RefreshCw, Activity, ShieldAlert, KeyRound,
  GitBranch, Bug, Network, BellRing, Lock, Plug, HelpCircle, CreditCard, Users, Unlock, Mail, FileCode2, Unlink, Boxes,
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
    title: "What ExactSurface is",
    icon: Radar,
    keywords: "overview easm attack surface external what is exactsurface",
    body: (
      <>
        <p>
          ExactSurface is a continuous <Term>External Attack Surface Management (EASM)</Term> platform.
          You add a domain you own; ExactSurface discovers everything that domain exposes to the internet
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
          <li><Term>TLS inspection</Term> — certificate chain, expiry, SANs (tlsx).</li>
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
          baseline. After it completes, ExactSurface switches to <Term>continuous</Term> mode: each phase
          re-runs on its own cadence (e.g. CVE watch every 15 min, subdomain enumeration every 6 h,
          full nuclei every 12 h). You configure these per program or account-wide in Settings.
        </p>
        <p>
          On top of the schedule there is an <Term>event-driven cascade</Term>: when re-enumeration
          finds a brand-new subdomain, ExactSurface immediately runs the downstream phases (probe, crawl,
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
    id: "triage",
    title: "What to look at first — interest & risk tags",
    icon: ShieldAlert,
    keywords:
      "interest triage critical high priority attention asset endpoint risk tag idor ssrf admin login jenkins auth bypass 401 403 what to look at first",
    body: (
      <>
        <p>
          A scan finds hundreds of hosts and endpoints. Two lightweight signals mark the handful worth a
          human&apos;s attention first — both are triage hints, not findings: they never trigger a scan or an
          alert on their own.
        </p>
        <p>
          <Term>Asset interest.</Term> Each probed host is triaged{" "}
          <Term>critical / high / medium / low</Term> from what httpx saw — its technology, page title,
          HTTP status, and hostname. An exposed Jenkins or Grafana, an{" "}
          <Code>Admin Dashboard</Code> page title, a <Code>401</Code> auth boundary, or a forgotten{" "}
          <Code>staging.</Code> host all raise it. Hosts flagged <Term>critical</Term> or <Term>high</Term>{" "}
          carry a coloured badge on the Assets tab; hover it to see <em>why</em> (e.g. &quot;Jenkins CI/CD
          exposed&quot;). It even infers a product hidden behind a reverse proxy from the hostname —{" "}
          <Code>kibana.</Code> behind nginx still gets flagged.
        </p>
        <p>
          <Term>Endpoint risk tags.</Term> Crawled and brute-forced URLs are tagged by the attack surface
          they expose — <Code>auth</Code>, <Code>admin</Code>, <Code>api</Code>, <Code>idor</Code>,{" "}
          <Code>ssrf</Code>, <Code>payment</Code>, <Code>exposure</Code> — read from the URL path and its
          query parameters (a <Code>?user_id=</Code> is an IDOR surface, a <Code>?url=</Code> an SSRF one).
          The tags show as badges next to each endpoint.
        </p>
      </>
    ),
  },
  {
    id: "domain-intel",
    title: "Domain intelligence — spoofing & registration",
    icon: Mail,
    keywords:
      "spf dmarc dkim email spoofing phishing whois rdap registrar expiry domain expires transfer lock dnssec registration",
    body: (
      <>
        <p>
          The first two questions an attacker answers about a domain, both from public
          records and without touching your servers: <Term>can I send mail as you</Term>, and
          <Term> is the registration itself weak</Term>. This runs first in every scan.
        </p>
        <p>
          <Term>Email spoofing.</Term> If you have no DMARC record — or one set to{" "}
          <Code>p=none</Code> — anyone can send mail that appears to come from your domain and
          it will be delivered. We read your SPF, DMARC and DKIM records and show the raw
          text alongside the verdict, so you can check it yourself. We also catch the subtle
          failures: <Code>+all</Code> (which authorises the entire internet to send as you),
          two SPF records (which makes receivers ignore SPF completely), and going over the
          10-lookup limit (which silently voids the policy while it still looks correct).
        </p>
        <p>
          <Term>Registration.</Term> A domain that expires is a total takeover — the website,
          the mail, and every login that trusts it. That date lives in a registrar account
          the security team usually can&apos;t see, so we surface it, along with whether the
          transfer lock and DNSSEC are enabled. Look for the panel on a program&apos;s{" "}
          <Term>Surface</Term> tab.
        </p>
      </>
    ),
  },
  {
    id: "js-mine",
    title: "JavaScript mining",
    icon: FileCode2,
    keywords:
      "javascript js bundle endpoints routes api paths source map sourcemap hidden admin internal hostnames spa",
    body: (
      <>
        <p>
          Your single-page app ships its whole routing table to every visitor. Inside those
          bundles are the API paths the UI calls, internal hostnames, and admin routes that
          never appear in a crawl. Reading them by hand is the most tedious part of a real
          assessment — the <Term>JS Mine</Term> tab does it for you.
        </p>
        <p>
          For each of your own bundles we extract paths and URLs, the hostnames the app talks
          to, and any published <Code>.map</Code> file (which lets anyone reconstruct your
          original, unminified source). Everything is filterable by tag, kind and bundle, and
          every row names the file it came from.
        </p>
        <p>
          It also <Term>compounds</Term>: paths found in JavaScript are added as endpoints, so
          the next run probes and scans them like any other. Third-party libraries are skipped
          deliberately — their routes are the library&apos;s, not yours.
        </p>
      </>
    ),
  },
  {
    id: "broken-links",
    title: "Broken-link hijacking",
    icon: Unlink,
    keywords:
      "broken link hijack dead link expired domain unclaimed social handle takeover outbound",
    body: (
      <>
        <p>
          A page of yours links out to a domain that has since expired, or a social handle
          that was deleted. Anyone can register that domain or claim that handle and instantly
          inherit the trust of your page linking to it — used for phishing, malware with a
          trusted referrer, and (when the dead link is a script) code running in your
          visitors&apos; browsers.
        </p>
        <p>
          We check the destinations of the outbound links you publish: a domain that no longer
          resolves is reported as <Term>registerable</Term>, and a social profile returning 404
          as a <Term>claimable handle</Term>. Nothing is registered or claimed — we only look.
        </p>
      </>
    ),
  },
  {
    id: "api-surface",
    title: "What each host publishes about itself",
    icon: Boxes,
    keywords:
      "robots sitemap swagger openapi graphql introspection well-known api schema paths hidden",
    body: (
      <>
        <p>
          Unintentional <Term>disclosure</Term> — targets hand over more than they realise.{" "}
          <Term>robots.txt</Term> is a public list of
          the paths an administrator wanted kept out of search results — which is exactly where
          an attacker looks first. <Term>sitemap.xml</Term> is the site&apos;s own inventory,
          often including pages nothing links to any more.
        </p>
        <p>
          <Term>API schemas</Term> are the big one. An exposed <Term>swagger.json</Term> or{" "}
          <Term>openapi.json</Term> documents every route, parameter and auth requirement in a
          single file, and <Term>GraphQL introspection</Term> does the same for GraphQL — one
          unauthenticated query returns the complete type system, including mutations that were
          never linked anywhere. We ask the server to describe itself; we never call a mutation
          or read data through it.
        </p>
        <p>
          Every path found this way is added to Endpoints, so content discovery and vulnerability
          scanning test it on the next run.
        </p>
      </>
    ),
  },
  {
    id: "misconfig",
    title: "CORS, open redirects and WAFs",
    icon: Boxes,
    keywords: "cors origin credentials open redirect phishing waf cloudflare firewall protected",
    body: (
      <>
        <p>
          <Term>CORS</Term> decides which other websites may read responses from yours. We send
          one request with a made-up origin and read the reply. If the server echoes that origin
          back <em>and</em> allows credentials, any site a logged-in user visits can read their
          authenticated data — that is reported High. A plain <Term>*</Term> on its own is not
          reported at all: it is how every public API is configured, and browsers refuse to send
          credentials with it. Flagging it would bury the real ones.
        </p>
        <p>
          An <Term>open redirect</Term> lets someone send a link that starts on your trusted
          domain and lands the victim elsewhere — the standard opening move for phishing, and a
          way to steal OAuth tokens. We only test redirect parameters your own pages already use,
          we point them at a reserved example domain, and we read the{" "}
          <Term>Location</Term> header without following it.
        </p>
        <p>
          <Term>WAF detection</Term> is context rather than a finding. Knowing a host sits behind
          Cloudflare explains why it returned less than its neighbour — and knowing which hosts
          have no WAF tells you where your unprotected surface actually is.
        </p>
      </>
    ),
  },
  {
    id: "hidden-params",
    title: "Hidden parameters",
    icon: Boxes,
    keywords: "hidden parameters arjun param discovery undocumented query string",
    body: (
      <>
        <p>
          Two very different costs, reported separately. The <Term>observed inventory</Term>{" "}
          is free — parameters already visible in URLs we already crawled, usually most of
          the real surface. The <Term>candidate probe</Term> costs requests: a bounded binary
          search over a curated wordlist (via <Term>arjun</Term>, with a built-in prober as a
          fallback if it is not installed) that finds parameters a page silently accepts but
          never links to anywhere.
        </p>
        <p>
          The probe only ever compares how a response changes when a parameter is added — it
          never submits a hostile value, so this is detection, not testing for injection. A
          parameter this finds is worth a look precisely because nobody documented it: an
          undocumented switch is the kind of thing that changes behaviour and gets forgotten.
        </p>
      </>
    ),
  },
  {
    id: "lookalikes",
    title: "Lookalike domains and dependency confusion",
    icon: Boxes,
    keywords: "typosquat lookalike phishing homoglyph dependency confusion npm package supply chain",
    body: (
      <>
        <p>
          <Term>Lookalike domains</Term> invert the usual question. Instead of what you own and
          forgot, this is what somebody else registered to impersonate you: dropped letters,
          neighbouring-key typos, homoglyphs (<Term>rn</Term> for <Term>m</Term>), and
          &ldquo;secure-&rdquo; prefixes. We generate the mutations phishing operators actually
          use, resolve them, and report only the ones that exist. One with <Term>MX</Term>{" "}
          records ranks higher — that is a phishing campaign with the mail plumbing already
          installed. It is off by default because it resolves several hundred names per run.
        </p>
        <p>
          <Term>Dependency confusion</Term> reads the package names inside your published
          JavaScript and asks the public npm registry whether anyone owns them. A name your build
          uses that nobody has claimed can be published by an attacker, whose code then runs
          inside your build with whatever it can reach. We only ever read registry metadata —
          registering the name defensively is your call, and the finding explains how.
        </p>
      </>
    ),
  },
  {
    id: "attack-paths",
    title: "Attack paths",
    icon: Boxes,
    keywords: "attack path chain narrative story correlation phases exploit route",
    body: (
      <>
        <p>
          On the <Term>Surface</Term> tab, findings that share a host are retold in the order an
          attacker would use them: an exposure leads to a foothold, which leads to credentials,
          which leads to access.
        </p>
        <p>
          A host needs findings spanning <Term>at least two</Term> stages of an attack before
          anything is called a path. A single finding is a finding — presenting it as a chain
          would overstate what we know, so we do not. Every step names the check it came from,
          so you can open the finding and verify the claim rather than taking our word for it.
        </p>
      </>
    ),
  },
  {
    id: "cloud-assets",
    title: "Connecting your cloud accounts",
    icon: Boxes,
    keywords: "cloud aws gcp azure digitalocean cloudlist credentials read-only inventory shadow it",
    body: (
      <>
        <p>
          DNS enumeration finds what somebody <em>published</em>. Your cloud provider knows
          what actually <Term>exists</Term> — the load balancer nobody pointed a name at, the
          VM left over from a migration. Turning on <Term>Cloud asset inventory</Term> asks
          your own AWS/GCP/Azure/DigitalOcean accounts what they are running.
        </p>
        <p>
          <Term>It needs read-only credentials, not SSO and not your console login.</Term>{" "}
          Create a dedicated read-only user or service account per provider (AWS{" "}
          <Term>ReadOnlyAccess</Term>, GCP <Term>roles/viewer</Term>, Azure{" "}
          <Term>Reader</Term>), put them in a <Term>cloudlist.yaml</Term>, mount it, and set{" "}
          <Term>EXACTSURFACE_CLOUDLIST_CONFIG</Term>. The module only ever lists resources, so
          write access buys nothing. Because you host this yourself, those credentials are
          read by your own deployment and never leave it.
        </p>
        <p>
          <Term>Results land in two places.</Term> Assets covered by a domain you have
          verified join the Surface tab and are monitored normally. Assets your cloud account
          owns that <em>no verified domain covers</em> are reported as a finding and are{" "}
          <Term>not scanned</Term> — your provider confirming you own something answers
          ownership, not authorisation. That second group is usually the interesting one: an
          asset nobody attached a monitored name to is often an asset nobody is watching. Add
          and verify the relevant domain to bring it into monitoring.
        </p>
      </>
    ),
  },
  {
    id: "cloud-buckets",
    title: "Exposed cloud storage",
    icon: Boxes,
    keywords: "cloud buckets s3 gcs azure blob storage public listable exposure",
    body: (
      <p>
        Derives likely S3/GCS/Azure bucket names from your domain (common naming patterns —
        the bare name, with environment suffixes, with the company name) and checks whether
        each one exists and, if so, whether it is <Term>publicly listable</Term>. A bucket
        that exists but is not public is not reported at all — it is not attributable to you
        without owning it, and listing it would just be noise. Only a bucket that actually
        lists its contents to anyone becomes a High finding.
      </p>
    ),
  },
  {
    id: "reverse-dns",
    title: "Reverse-DNS sweep",
    icon: Boxes,
    keywords: "reverse dns ptr sweep asn dedicated ip range hosts",
    body: (
      <p>
        PTR-sweeps the IP ranges <Term>confirmed to be yours</Term> — never a name you have
        not verified — for hosts that exist in that address space but were never published in
        any DNS record. It only runs on ranges that have already earned{" "}
        <Term>dedicated</Term> status (your domain&apos;s real announced ASN, not a
        self-declared claim), and is capped at 8192 addresses per range so one very large
        allocation cannot turn into an unbounded sweep. Off by default for exactly that
        reason — it is the most request-heavy discovery module in the product.
      </p>
    ),
  },
  {
    id: "modules",
    title: "Turning modules on and off",
    icon: Boxes,
    keywords:
      "modules enable disable turn off schedule cadence dependency required essential settings",
    body: (
      <>
        <p>
          Every scan step is a module you control, on a program&apos;s page under{" "}
          <Term>Scan modules</Term>. Each has its own re-run schedule too, under{" "}
          <Term>Scan schedule</Term>.
        </p>
        <p>
          <Term>Modules depend on each other.</Term> Crawling needs live-host probing;
          JavaScript mining and broken-link hijacking need crawling. So turning one off also
          stops everything downstream — the switch tells you exactly what that costs before you
          flip it, and anything skipped says why (&quot;needs Crawling &amp; archives, which is
          off&quot;).
        </p>
        <p>
          <Term>Subdomain discovery and live-host probing cannot be turned off.</Term> Every
          other module reads their output, so without them there is nothing to scan.
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
          subdomain. ExactSurface detects two signals:
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
    id: "bypass403",
    title: "403 / 401 bypass",
    icon: Unlock,
    keywords:
      "403 401 bypass forbidden access control x-original-url x-forwarded-for path normalisation header method endpoints button blue label attacker detection",
    body: (
      <>
        <p>
          A <Code>403 Forbidden</Code> or <Code>401</Code> isn&apos;t always a real wall. A mis-configured
          proxy or app will often hand over the &quot;protected&quot; page anyway if you ask the right way —
          and an attacker who hits a 403 tries exactly those tricks before moving on. This tool runs them
          for you, on your own surface, so you find the hole first.
        </p>
        <p>
          It&apos;s <Term>on-demand only</Term>: open the <Term>Endpoints</Term> tab and, when there are
          forbidden endpoints, a <Term>Try 403 bypass</Term> button appears. It is <em>not</em> part of the
          scan pipeline and never runs on a schedule. Progress streams into the <Term>Activity</Term> tab
          like any scan (&quot;trying X-Original-URL …&quot;). Any endpoint that turns out to be bypassable
          gets a blue <Term>403 bypassed</Term> label — click it for the exact request (technique, headers,
          and a ready-to-run <Code>curl</Code>).
        </p>
        <p>
          The techniques are the canonical ones: forwarding headers (<Code>X-Forwarded-For</Code>,{" "}
          <Code>X-Real-IP</Code>), URL-rewrite headers (<Code>X-Original-URL</Code>,{" "}
          <Code>X-Rewrite-URL</Code>), and path-normalisation quirks (<Code>/admin/</Code>,{" "}
          <Code>/admin/..;/</Code>, encoded characters). A hit is re-confirmed with a second request to
          shed load-balancer noise before it&apos;s recorded.
        </p>
        <p>
          <Term>This is still detection, not exploitation.</Term> It only uses <Term>safe HTTP methods</Term>{" "}
          (never POST/PUT/DELETE — nothing that could change data), never follows redirects, never changes
          the host it talks to, and sends the same benign probe an attacker would — it just reports what got
          through. It obeys the same rules as every scan: a current authorization, in-scope hosts only, and
          the ≤10 req/s politeness cap (§9b, §3.8b).
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
          right now). ExactSurface stores only a <Term>masked</Term> value and a keyed hash — never the plaintext.
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
    id: "template-watch",
    title: "New-template watch",
    icon: Bug,
    keywords: "nuclei watch new template baseline rescan detection updates",
    body: (
      <p>
        Nuclei&apos;s template library grows constantly — a new CVE or misconfiguration check
        ships and suddenly applies to hosts that were already scanned and looked clean at the
        time. This module <Term>baselines</Term> which templates are relevant to your
        fingerprinted tech stack, and when a newly published template joins that relevant set,
        it triggers a targeted re-scan instead of waiting for the next full scan — so a fresh
        detection reaches you as soon as it exists, not on the next scheduled cadence.
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
        Ports carry no severity from the scanner, so ExactSurface grades by exposure: a directly-reachable
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
    keywords:
      "scope safety authorization verification dedicated shared cidr consent politeness asn asnmap confirmed unconfirmed ip scope",
    body: (
      <>
        <p>
          Before any active scanning, you must <Term>verify ownership</Term> of the domain (DNS/HTTP token)
          and grant <Term>authorization</Term>. A central scope engine then gates every action: shared
          cloud/CDN IPs get HTTP-only checks, only infrastructure confirmed as dedicated to you is
          port-scanned or actively probed, and a hard deny-list is never overridable. Scanning is
          rate-limited for politeness.
        </p>
        <p>
          <Term>Why a CIDR you list isn&apos;t automatically port-scanned.</Term> Proving you control a
          domain doesn&apos;t prove you own every IP its subdomains point at — so listing a range in your
          authorization only <em>requests</em> it. Before each scan we look up the ASN actually announcing
          your verified apex and check the range against it. Confirmed → <Code>dedicated</Code>, full
          scanning, recorded on the authorization record as <Code>asnmap:&lt;range&gt;</Code>. Not
          confirmed → <Code>unconfirmed</Code>, HTTP-layer checks only. A third-party CDN edge is{" "}
          <em>never</em> promoted, even if the ASN matches — that hardware is Cloudflare&apos;s, not yours.
        </p>
        <p>
          This is re-checked on every run, so a range you stop announcing drops back to HTTP-only
          automatically. If ASN data is unavailable we confirm nothing rather than guess. Own the cloud
          your domain runs on and want its shared ranges scanned? Use the explicit{" "}
          <Term>scan shared infra</Term> opt-in on the program instead.
        </p>
      </>
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
    id: "plans",
    title: "Plans & domain limits",
    icon: CreditCard,
    keywords: "plan limit domains quota free pro business enterprise upgrade downgrade 402 billing",
    body: (
      <>
        <p>
          Your plan caps how many <Term>domains</Term> (programs) you can scan:{" "}
          <Code>Free</Code> 1 · <Code>Pro</Code> 5 · <Code>Business</Code> 25 ·{" "}
          <Code>Enterprise</Code> unlimited. Adding one past the cap is refused with a
          &quot;plan allows N domain(s)&quot; message.
        </p>
        <p>
          Limits are checked <em>both</em> when you add a domain <em>and</em> before any scan
          starts — so a plan change takes effect immediately, with no restart or re-login.
        </p>
        <p>
          <Term>Downgrading never deletes anything.</Term> If you drop from Pro to Free with 5
          domains, all 5 keep their history and stay readable — but only the allowance (the{" "}
          <em>oldest</em> domain first) continues to be scanned. The rest are skipped by the
          scheduler and report &quot;outside that allowance&quot; if you try to scan them by hand.
          Upgrade again and they resume on the next tick.
        </p>
      </>
    ),
  },
  {
    id: "account",
    title: "Account & email verification",
    icon: Lock,
    keywords: "email verification verify signup account link expired resend confirm inbox",
    body: (
      <>
        <p>
          Signing up sends a <Term>verification email</Term> with a single-use link. The link expires
          after <Term>24 hours</Term>, and using it once consumes it — an old link will report
          &quot;couldn&apos;t verify&quot;. You can request a fresh one from the verification page
          (rate-limited to one per minute).
        </p>
        <p>
          Whether verification is <em>required</em> before you can add a program is a deployment
          setting (<Code>REQUIRE_EMAIL_VERIFICATION</Code>) — it is off in local/dev so you aren&apos;t
          blocked, and on in production. Self-hosting? Email delivery is provider-agnostic: the
          default <Code>log</Code> transport just prints the link into the server log (no account
          needed), and any SMTP provider (Resend, Brevo, SES, Postmark, Mailgun) works by setting
          <Code>EMAIL_TRANSPORT=smtp</Code> plus SMTP credentials.
        </p>
      </>
    ),
  },
  {
    id: "access",
    title: "Team access & permissions",
    icon: Users,
    keywords:
      "rbac role permission group owner member viewer iam access control team user invite settings manage view escalation revoke",
    body: (
      <>
        <p>
          The person who signs up is the <Term>owner</Term>. The owner holds every permission and is
          the only one who can add teammates and decide what they can do — everything is managed under{" "}
          <Term>Settings → Permission groups / Team members</Term>.
        </p>
        <p>
          Access works AWS-IAM style: you compose a <Term>permission group</Term> (a named set of
          permissions) and add members to it. A member&apos;s access is the union of their groups.
          A brand-new member has <Term>no group and therefore no access at all</Term> until the owner
          places them in one — nothing is visible by default. A read-only <Code>Viewer</Code> group is
          seeded for you; it can be renamed or re-permissioned but not deleted.
        </p>
        <div className="space-y-2">
          <Q q="View">
            Read everything — overview, programs, assets, findings, DNS, activity. No changes.
          </Q>
          <Q q="Manage programs">
            Add/remove domains, verify, run scans, toggle modules, mute assets. Implies View.
          </Q>
          <Q q="Manage settings">
            API keys, integrations, notification channels, alert policy, schedules. Implies View.
          </Q>
        </div>
        <p>
          Two things are deliberately <Term>owner-only and can never be delegated</Term>: managing
          teammates/groups, and the highest-stakes program actions (deleting a program and creating the
          scanning-authorization record). This makes privilege escalation impossible — no permission a
          member can be granted lets them expand their own access. Permission changes take effect{" "}
          <Term>immediately</Term> (they&apos;re re-checked on every request), so removing someone from a
          group revokes their access at once, without waiting for them to log out. An API key inherits its
          creator&apos;s current permissions, so revoking the creator revokes the key.
        </p>
      </>
    ),
  },
  {
    id: "section-refs",
    title: "Those § numbers explained",
    icon: BookOpen,
    keywords:
      "section reference numbering §9b §3.8b §9c §3.9 §15 spec what does mean symbol paragraph legend glossary",
    body: (
      <>
        <p>
          You&apos;ll see markers like <Code>§9b</Code> or <Code>§3.8b</Code> in some notes (e.g.
          &quot;ports skipped — §9b&quot;). The <Term>§</Term> symbol just means &quot;section&quot; — it
          points at the paragraph of ExactSurface&apos;s design spec that a rule comes from. They&apos;re there
          so a decision is traceable to <em>why</em> it exists, not jargon you need to memorise. The ones
          you&apos;ll actually meet:
        </p>
        <div className="space-y-2">
          <Q q="§9b — authorization to scan">
            You must prove you own a domain before it&apos;s scanned, and owning the domain doesn&apos;t
            authorise scanning every IP it points at. This is why a CDN/shared host gets HTTP-only checks,
            and why ports/brute-force are withheld until an IP is confirmed dedicated to you.
          </Q>
          <Q q="§3.8b — politeness / rate limiting">
            Every request to a target is capped (≤10/sec per host) so scanning never looks like abuse to
            the host or its provider. This is why a large scan is paced rather than instant.
          </Q>
          <Q q="§3.9 — CDN / cloud ranges">
            Known Cloudflare/AWS/Akamai/… IP ranges get HTTP-layer probing only — that hardware belongs to
            the provider, not you.
          </Q>
          <Q q="§9c — exposed-secret handling">
            A found secret is stored masked + hashed, never in plaintext, and never sent in an alert.
          </Q>
          <Q q="§15 — signal quality targets">
            The metrics that make the product trustworthy: time-to-first-alert, the false-positive rate
            (target under 5%), and zero AUP complaints.
          </Q>
        </div>
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
        <Q q="Does ExactSurface ever attack or change my systems?">
          No. It is detection-only: it observes, fingerprints, and reports. It never exploits, writes, or
          disrupts.
        </Q>
        <Q q="Why does a large scan take a while?">
          Every request ExactSurface sends a target — probing, crawling, content discovery, vulnerability
          checks — is <Term>paced to stay under a per-target rate cap</Term> so scanning never looks like
          abuse to the host or its cloud provider. A domain with many subdomains or a big content-discovery
          run is therefore deliberately spread out rather than run flat-out. Politeness is a hard
          constraint, not a setting.
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
            How ExactSurface works, what each signal means, and the conditions behind it.
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
