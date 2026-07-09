// Human-friendly labels + one-line descriptions for each pipeline / stage, so the
// activity feed explains what's happening under the hood instead of showing raw
// names like "ingest" or "cve_watch".
export const PIPELINE_INFO: Record<string, { label: string; desc: string }> = {
  full: {
    label: "Full scan",
    desc: "The complete pipeline: discover → probe → crawl → scan → secrets.",
  },
  ingest: {
    label: "Discover",
    desc: "Find subdomains (subfinder, crt.sh, DNS) and resolve them to hosts.",
  },
  probe: {
    label: "Probe",
    desc: "Check which hosts are alive and fingerprint their tech stack (httpx).",
  },
  tls: {
    label: "TLS",
    desc: "Inspect certificate chains + expiry on alive hosts (tlsx).",
  },
  service_scan: {
    label: "Services",
    desc: "Identify service/version on open ports (nmap -sV).",
  },
  crawl: {
    label: "Crawl",
    desc: "Gather endpoints from archives (gau/wayback) and active crawling (katana).",
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
};

export function pipelineLabel(name: string): string {
  return PIPELINE_INFO[name]?.label ?? name;
}

export function pipelineDesc(name: string): string {
  return PIPELINE_INFO[name]?.desc ?? "";
}
