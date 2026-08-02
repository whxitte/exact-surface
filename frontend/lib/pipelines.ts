// Human-friendly labels + one-line descriptions for each pipeline / stage, so the
// activity feed explains what's happening under the hood instead of showing raw
// names like "ingest" or "cve_watch".
export const PIPELINE_INFO: Record<string, { label: string; desc: string }> = {
  full: {
    label: "Full scan",
    desc: "The complete pipeline: discover → probe → crawl → scan → secrets.",
  },
  domain_intel: {
    label: "Domain intel",
    desc: "Email spoofability (SPF/DMARC/DKIM) and domain registration risk — fully passive.",
  },
  cloud_assets: {
    label: "Cloud assets",
    desc: "Ask your cloud accounts what's running, so nothing goes unmonitored (needs credentials).",
  },
  reverse_dns: {
    label: "Reverse DNS",
    desc: "PTR-sweep ASN-confirmed ranges for hosts that exist but were never published in DNS.",
  },
  ingest: {
    label: "Discover",
    desc: "Find subdomains (subfinder, crt.sh, DNS) and resolve them to hosts.",
  },
  uncover: {
    label: "Uncover",
    desc: "Passive host discovery via Shodan/Censys (needs an API key).",
  },
  probe: {
    label: "Probe",
    desc: "Check which hosts are alive and fingerprint their tech stack (httpx).",
  },
  tls: {
    label: "TLS",
    desc: "Inspect certificate chains + expiry on alive hosts (tlsx).",
  },
  takeover: {
    label: "Takeover",
    desc: "Check dangling CNAMEs for subdomain-takeover risk.",
  },
  service_scan: {
    label: "Services",
    desc: "Identify service/version on open ports (nmap -sV).",
  },
  crawl: {
    label: "Crawl",
    desc: "Gather endpoints from archives (gau/wayback) and active crawling (katana).",
  },
  js_mine: {
    label: "JS mining",
    desc: "Extract endpoints, secrets and internal paths from JavaScript bundles.",
  },
  api_surface: {
    label: "API surface",
    desc: "Detect exposed API schemas, admin paths and debug/status endpoints.",
  },
  http_misconfig: {
    label: "HTTP config",
    desc: "CORS misconfiguration, open redirects, and WAF/CDN fingerprinting.",
  },
  param_discovery: {
    label: "Hidden params",
    desc: "Find undocumented parameters a URL silently accepts.",
  },
  broken_links: {
    label: "Broken links",
    desc: "Detect dangling links and hijackable references to unclaimed domains.",
  },
  scan: {
    label: "Scan",
    desc: "Run Nuclei detection templates against discovered endpoints.",
  },
  secrets: {
    label: "Secrets",
    desc: "Fetch endpoint bodies and detect exposed secrets (stored masked).",
  },
  port_scan: {
    label: "Ports",
    desc: "Discover open ports on confirmed-dedicated hosts (naabu).",
  },
  content_discovery: {
    label: "Content",
    desc: "Bruteforce hidden paths and files on dedicated hosts (feroxbuster).",
  },
  cve_watch: {
    label: "CVE watch",
    desc: "Match fingerprinted tech against new CVE / CISA-KEV feeds.",
  },
  correlate: {
    label: "Correlate",
    desc: "Chain findings across modules into prioritized issues.",
  },
  github_osint: {
    label: "GitHub OSINT",
    desc: "Search public GitHub for leaked secrets referencing the domain.",
  },
  notify: {
    label: "Notify",
    desc: "Deliver genuinely-new findings to configured notification channels.",
  },
  dork: {
    label: "Dorking",
    desc: "Query search engines for indexed exposures.",
  },
  cloud_buckets: {
    label: "Cloud buckets",
    desc: "Guess and check S3/GCS/Azure bucket names derived from your domain.",
  },
  nuclei_watch: {
    label: "Template watch",
    desc: "Alert when a newly published detection template matches your tech stack.",
  },
  supply_chain: {
    label: "Dep. confusion",
    desc: "Internal package names referenced in your JS that nobody has claimed on npm.",
  },
  typosquat: {
    label: "Lookalikes",
    desc: "Registered lookalike domains set up to phish your staff and customers.",
  },
};

export function pipelineLabel(name: string): string {
  return PIPELINE_INFO[name]?.label ?? name;
}

export function pipelineDesc(name: string): string {
  return PIPELINE_INFO[name]?.desc ?? "";
}
