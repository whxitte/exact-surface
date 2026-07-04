# VANTARI — Master Build Prompt (v2, Engineered)

> **Instruction to Claude Code:** Read this entire document before writing a single file. Build in the exact phase order in §7. Do not build the frontend before the API contract is stable (Phase E, not before). Do not add a module that duplicates a Phase-1 module. Every network-touching module MUST call the central scope engine (§3.9) before any I/O — no exceptions, enforced by code review and by a runtime guard.
>
> This is v2. It supersedes the original build prompt. It folds in four production-blocking corrections and a set of architecture decisions made by a security engineer who has run this kind of infrastructure. Where this document changes an earlier decision, the change is marked **[v2]** with the rationale.

---

## 0. Reading Guide — What Changed in v2 and Why

Four corrections from review, all accepted, all integrated in place:

1. **Masscan is disabled in v1.** Running a mass port scanner from shared cloud infra (DigitalOcean/AWS/GCP) violates their AUP and gets the account — and therefore the whole platform — terminated, often without warning. **[v2]** v1 uses `naabu` (ProjectDiscovery's connect/SYN scanner) with a hard global rate cap and per-target throttle. Masscan returns only when Vantari has dedicated scanning netblocks. See §3.8b.
2. **Domain ownership ≠ scanning authorization for every resolved IP.** A verified apex proves DNS control; it does not authorize aggressive scanning of the CDN/cloud shared IPs a subdomain resolves to. **[v2]** A resolved IP is classified before any active work; shared CDN/cloud IPs get HTTP-layer probing only. See §3.9 and §9b.
3. **The "Days 1–50" timeline is logical phases, not a calendar.** This is solo, part-time work. Phase exits are mandatory gates, not dates. See §7 header.
4. **The $5 droplet estimate is wrong by an order of magnitude.** Realistic baseline is a 4 GB / 2 vCPU worker plus a separate API host; Atlas M0 is dev-only. See §3.8.

Beyond the review, v2 makes these architecture decisions (each has an ADR in §17):

- **[v2] Central scope-enforcement engine** (`core/scope.py`) is a first-class, non-bypassable subsystem — the single most important safety and legal control in the product.
- **[v2] Distributed task queue** (Redis + `arq`) replaces the "daemon of async loops." Scheduler enqueues, a stateless worker pool executes. This is what makes multi-tenant scaling, fairness, and back-pressure possible.
- **[v2] ProjectDiscovery-first toolchain** (`subfinder`, `dnsx`, `httpx`, `naabu`, `katana`, `nuclei`, `tlsx`, `asnmap`, `cloudlist`, `uncover`, `notify`). One maintained ecosystem, JSON everywhere, built-in rate controls, designed to be chained.
- **[v2] Exposed-secret handling policy.** Vantari must never become a plaintext honeypot of its customers' leaked secrets. Store masked value + hash + locator; encrypt any retained snippet; short retention; never transmit full secret in notifications. See §9c.
- **[v2] Finding lifecycle state machine** replaces the bare `is_new` boolean for triage.
- **[v2] CVE match confidence scoring** — fingerprint→CPE→CVE is noisy; low-confidence matches are suppressed by default, KEV matches are always escalated. See §6 module 24.
- **[v2] Nuclei safe-template policy** — exclude `dos,intrusive,fuzz`; document the detection/exploitation boundary in enforceable terms. See §9d.
- **[v2] Per-program authorization record** — a stored, auditable authorization artifact per program, with IP-scope confirmation via WHOIS/ASN. See §9b.

MongoDB stays (ADR-0001 documents why, and why Postgres+JSONB was the close runner-up).

---

## 1. What Vantari Is

Vantari is a **continuous external attack-surface intelligence platform** for organizations that build and ship software — and especially for the web/app agencies and product teams that constantly spin up staging, preview, and demo environments and forget them.

The product answers one question, continuously, for every domain a customer owns: **"What does an external attacker see right now, and what can they do with it?"** Not the CMDB. Not the last pentest. What is *live on the internet at this moment*, discoverable by a motivated attacker using public tooling.

Vantari runs as an outside-in simulated adversary — **detection only, never exploitation** (§9d draws the line precisely). It enumerates subdomains, resolves and probes them, fingerprints tech stacks, discovers exposed files/directories/parameters, extracts references to leaked secrets from JavaScript and archived URLs, monitors GitHub for leaked credentials, watches CVE/KEV feeds for issues matching each customer's live stack, and alerts within minutes of a new exposure appearing.

**The defining behavior is speed plus state-awareness.** When a dev team pushes `staging-new.customer.com` at 3:47pm, Vantari has discovered it, probed it, fingerprinted it, and queued the first scan within minutes — and if `.env` is exposed at the web root, an alert reaches the security team fast. The state-awareness is what keeps that from becoming 100 duplicate alerts on every re-scan: one alert per genuinely new fact.

**Agency-focused differentiator [v2]:** first-class detection of *ephemeral* environments — Vercel/Netlify/Cloudflare Pages preview URLs, `staging.`/`dev.`/`uat.`/`demo.` subdomains, and forgotten one-off deploys. These are where agencies leak the most and where no incumbent focuses.

---

## 2. Market Positioning

The EASM market (Bitsight, CyCognito, Palo Alto Cortex Xpanse, Wiz, Rapid7, Mandiant) is enterprise-priced, sales-led, and slow to onboard. Vantari differentiates on four axes:

1. **Speed to first finding** — minutes, not weeks. New subdomain → alert fast.
2. **Attacker fidelity** — the actual tooling attackers use (Nuclei, Katana, naabu, wordlist fuzzing), not sanitized enterprise scanners.
3. **Signal quality** — state-awareness + suppression + a finding state machine means one alert per real issue, and a low false-positive rate (the metric that makes or breaks EASM credibility).
4. **Self-serve onboarding** — add a domain, verify ownership, scanning begins. No sales call.

Vantari is external, agentless, continuous, attacker-perspective. It does **not** compete with Nessus/OpenVAS/Qualys (internal, agent-based).

---

## 3. Architectural Principles (Non-Negotiable)

If a proposed change violates one of these, refuse it and explain.

**3.1 State-awareness.** Every asset, endpoint, finding, secret, port, and CVE match is persisted with `first_seen`, `last_seen`, `is_new`, and a stable content-hash fingerprint (§5b defines the hash inputs per entity). Modules read state before doing expensive work. Re-scanning an unchanged asset every hour is a bug.

**3.2 Idempotency.** Every write is an upsert — `$setOnInsert` for immutable fields, `$set` for volatile ones. Re-running any module N times yields the same DB state as running it once. `is_new=True` fires exactly once per genuine insert.

**3.3 Modularity.** Every scanner/prober/enumerator/enricher is a standalone module with one interface:
```python
async def run(ctx: RunContext) -> RunResult: ...
```
where `RunContext` carries `tenant_id`, `program_id`, `target`, the scope engine handle, the rate limiter, and settings. Modules never reach into each other's internals. Swapping Subfinder for Amass is config, not code.

**3.4 Multi-tenancy from line one.** Every document has `tenant_id`. Every query filters by `tenant_id`. Every endpoint validates the caller's `tenant_id`. Every compound index leads with `tenant_id`. Cross-tenant reads are impossible by construction (§3.7), not by convention.

**3.5 Async everywhere.** `asyncio` throughout. `motor` for MongoDB, `aiohttp` for HTTP, `asyncio.create_subprocess_exec` for tools — every subprocess has a timeout, a hard kill on timeout, jitter, and a rate budget. No blocking I/O in the hot path.

**3.6 Cross-platform via containers.** Linux-native tooling ships in one Alpine/Debian-slim Docker image (`Dockerfile.pipeline`). Same image runs on Linux, macOS (Docker Desktop), Windows (WSL2). API and frontend run natively (Python 3.11+ / Node 20+) or in their own images.

**3.7 Zero-trust internally.** Customer data never leaves its tenant. Any endpoint returning data verifies tenant ownership via an explicit dependency (`require_program_ownership`) *before* touching a collection. Ownership checks are centralized in `api/deps.py`; a route that queries a collection without going through them is a bug caught in review.

**3.8 Cost discipline — realistic baseline [v2].** Viable on entry-tier resources for dev and single-tenant testing, but sized honestly:
- **Pipeline worker:** minimum **4 GB RAM / 2 vCPU** (e.g., $20–40/mo VM). Subfinder + httpx + nuclei + katana + naabu + feroxbuster on a real target with >50 subdomains will OOM a 1 GB box. Keep the worker separate from the API.
- **API + frontend:** small host is fine (1–2 GB).
- **Datastore:** Atlas **M0 is development only** (512 MB). Production requires **M10+** or self-hosted MongoDB with backups.
- **Redis:** small managed instance or co-located; used for the task queue and rate-limit token buckets.
- **Production multi-tenant:** auto-scaling stateless workers sized to concurrent-scan load, not a single droplet. Concurrency is bounded by the queue and the global rate limiter, so cost scales with load, not tenant count.

**3.8b Scanning rate limits & cloud-provider compliance [v2].** Port/aggressive scanning from shared cloud infra violates provider AUP and draws abuse reports from targets' ISPs. The pipeline enforces, centrally:
- **Global politeness limiter** (Redis token bucket) keyed by **(target IP, ASN)**: default **≤ 10 packets/requests per second per target IP**, regardless of how many jobs touch it concurrently.
- **Per-target cool-off** between scan phases.
- **naabu** is the v1 port scanner with `-rate` capped and `-c` (concurrency) bounded; **masscan is DISABLED in v1** (feature-flagged off, config-guarded).
- **Provider-range exclusion / de-rating:** known AWS/GCP/Azure/Cloudflare/Akamai/Fastly ranges are loaded from maintained CIDR feeds; scanning against them is limited to HTTP-layer probing (§3.9). The exclusion list is a first-class, updatable dataset, not a hardcoded constant.
- Egress source IPs the platform scans from are documented and, in production, ideally dedicated/abuse-contact-registered netblocks before Masscan is ever re-enabled.

**3.9 Central scope enforcement [v2] — the most important control in the product.** `core/scope.py` exposes:
```python
def classify_ip(ip: str) -> IpClass          # DEDICATED | CDN | CLOUD_SHARED | PRIVATE | RESERVED | UNKNOWN
async def assert_in_scope(ctx, target) -> ScopeDecision   # raises OutOfScope, or returns allowed action set
```
Every module calls `assert_in_scope` before any network I/O. A network call that skips it is a defect. The engine **denies by construction**:
- RFC1918 (10/8, 172.16/12, 192.168/16), loopback (127/8), **link-local incl. cloud metadata (169.254.0.0/16 → 169.254.169.254)**, CGNAT (100.64/10), multicast, and reserved ranges — always, no override.
- Any host not tied to a **verified program** for the calling `tenant_id`.
- The program's explicit **exclusion list** (customer-supplied out-of-scope hosts/CIDRs).
- Targets whose IP classifies as `CDN`/`CLOUD_SHARED` get a **reduced action set** (HTTP-layer probing only; no port scan, no aggressive Nuclei) unless the customer has explicitly acknowledged and authorized that shared infra (§9b).

**3.10 Detection-only ethical boundary [v2, enforceable].** Vantari detects; it does not exploit. Operationally: **no payload that modifies target state, exfiltrates data beyond a benign proof, or causes denial of service.** Enforced by the Nuclei template policy in §9d (exclude `dos,intrusive,fuzz`; pin templates; review the tag set). This boundary is also a term of service (§9).

---

## 4. Directory Structure

Enforce this layout. Deviations require an ADR (§17). Changes from v1 are marked **[v2]**.

```
vantari/
├── docker/
│   ├── Dockerfile.pipeline        # recon toolchain (see §6b); masscan present but disabled by flag
│   ├── Dockerfile.api             # slim Python 3.11 + FastAPI
│   ├── Dockerfile.frontend        # Node 20 + Next.js
│   ├── Dockerfile.worker          # [v2] pipeline image + arq worker entrypoint
│   ├── docker-compose.yml         # local dev: api, worker, scheduler, mongo, redis, frontend
│   └── docker-compose.prod.yml
├── core/                          # pure logic, no external I/O
│   ├── models.py                  # Pydantic v2; every model extends TenantScopedModel
│   ├── config.py                  # Pydantic Settings, .env driven
│   ├── logging.py                 # Loguru + tenant_id/scan_id context
│   ├── scope.py                   # [v2] central scope engine (§3.9)
│   ├── ratelimit.py               # [v2] Redis token-bucket politeness limiter (§3.8b)
│   ├── fingerprint.py             # tech-stack classifier + asset interest scorer
│   ├── hashing.py                 # [v2] content-hash fingerprint per entity (§5b)
│   ├── severity.py                # finding severity + CVSS/EPSS mapping
│   ├── lifecycle.py               # [v2] finding state machine (§5c)
│   ├── suppression.py             # alert de-dup + suppression windows
│   ├── secrets_policy.py          # [v2] masking/encryption for exposed secrets (§9c)
│   ├── tenant.py                  # tenant context
│   └── errors.py                  # exception hierarchy (incl. OutOfScope, RateLimited)
├── db/                            # one file per collection; all async (motor)
│   ├── mongo.py                   # connection + index bootstrap
│   ├── tenants.py                 # [v2]
│   ├── programs.py
│   ├── authorizations.py          # [v2] per-program authorization records (§9b)
│   ├── assets.py
│   ├── endpoints.py
│   ├── findings.py
│   ├── secrets.py
│   ├── leaks.py
│   ├── ports.py
│   ├── cves.py
│   ├── deltas.py
│   ├── scope_cache.py             # [v2] resolved-IP classification cache
│   └── audit.py
├── modules/                       # tool wrappers, one per capability (§6)
│   ├── recon/    (subfinder, amass, crtsh, uncover, dnsx, dns_bruteforce, alterx)
│   ├── probing/  (httpx, tls_inspector, header_analyzer)
│   ├── scanning/ (nuclei, secretfinder, dalfox, nikto)
│   ├── crawling/ (katana, waybackurls, gau, js_analyzer)
│   ├── ports/    (naabu, nmap, nuclei_network)     # [v2] naabu replaces masscan in v1
│   ├── content_discovery/ (feroxbuster, ffuf, wordlist_selector)
│   ├── dorking/  (google, brave, serpapi, templates)
│   ├── osint/    (github, asn_mapper, cloud_buckets, wayback, preview_env)  # [v2] preview_env
│   ├── intelligence/ (cve_feed, nuclei_templates, delta_monitor, correlator)
│   ├── notification/ (discord, telegram, slack, email, webhook, router)
│   └── reporting/ (html_report, pdf_report, hackerone_report, executive_summary)
├── pipelines/                     # orchestrators — compose modules into a workflow
│   ├── ingest.py  probe.py  scan.py  crawl.py  port_scan.py  content_discovery.py
│   ├── dork.py  github_osint.py  cve_watch.py  delta_watch.py
├── queue/                         # [v2] task queue layer
│   ├── worker.py                  # arq worker: pulls jobs, sets scope+ratelimit ctx, runs pipeline
│   ├── scheduler.py               # state-aware enqueuer with per-tenant fair scheduling
│   ├── jobs.py                    # job definitions + serialization
│   └── fairness.py                # weighted fair queuing across tenants
├── daemon/
│   ├── main.py                    # supervises scheduler + N workers (or they run as separate procs)
│   ├── health.py                  # pre-flight: binaries + DB + redis + config + scope feeds
│   └── metrics.py                 # Prometheus metrics endpoint
├── api/                           # FastAPI SaaS layer
│   ├── main.py  auth.py  deps.py  rate_limit.py
│   ├── routes/  (auth, tenants, programs, domain_verification, authorizations[v2],
│   │             assets, endpoints, findings, ports, secrets, leaks, dork_results,
│   │             cve_matches, deltas, reports, notifications, scan_runs, stats, health)
│   └── ws/stream.py               # websocket live finding stream
├── frontend/                      # Next.js 14 + shadcn/ui + Tailwind (Phase E)
├── scripts/  (seed_dev.py, migrate.py, backup.py, update_scope_feeds.py[v2])
├── tests/    (unit/ integration/ e2e/ security/)
├── docs/     (ARCHITECTURE.md, ADRs/, API.md, DEPLOYMENT.md, SECURITY.md)
├── .env.example  pyproject.toml  requirements.txt  Makefile  README.md
```

---

## 5. Data Model

### 5a. Base

```python
class TenantScopedModel(BaseModel):
    tenant_id: str = Field(..., description="Tenant this record belongs to")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
```
Every domain model extends it. Enforced by review.

Minimum compound indexes on every collection:
- `(tenant_id, program_id)` — dominant query pattern
- `(tenant_id, is_new)` — "new today"
- `(tenant_id, severity, first_seen)` — triage dashboards
- `(tenant_id, fingerprint)` **unique** — dedup / idempotent upsert key

### 5b. Content-hash fingerprints [v2] — define exactly what goes in each hash

The upsert key. Volatile fields (timestamps, counters) are **excluded**; identity-defining fields are **included**. `sha256` over a canonical, sorted JSON of:
- **Asset:** `(program_id, hostname)` — resolution changes are deltas, not new assets.
- **Endpoint:** `(program_id, method, normalized_url)` — query values normalized/stripped for identity.
- **Port:** `(program_id, ip, port, protocol)`.
- **Finding:** `(program_id, template_id_or_check, matched_at_url_or_ip, extracted_key_locator)` — *not* the response body (bodies change; the finding is the same).
- **Secret:** `(program_id, secret_hash, source_locator)` where `secret_hash` is a keyed hash of the secret value (never the plaintext).
- **CVE match:** `(program_id, cve_id, asset_fingerprint, cpe)`.
`core/hashing.py` owns these; any new entity adds its rule there.

### 5c. Finding lifecycle state machine [v2]

Replace the bare `is_new` boolean with an explicit state, kept alongside `is_new`:
```
NEW ──triage──▶ TRIAGED ──▶ CONFIRMED
  │                     └──▶ FALSE_POSITIVE
  │                     └──▶ ACCEPTED_RISK
  ▼
CONFIRMED ──fix verified──▶ RESOLVED ──reappears──▶ REGRESSED (=NEW again, alerts once)
```
- Suppression: a `FALSE_POSITIVE` fingerprint is suppressed for a configurable window (default 7 days) and does not re-alert unless its content-hash inputs change.
- `RESOLVED` → reappearance re-opens as `REGRESSED` and alerts exactly once (idempotent).
- State transitions are audit-logged with actor + timestamp + diff.

### 5d. Authorization record [v2]

Per program: `authorized_by` (actor), `authorized_at`, `verification_method` (DNS_TXT | HTTP_FILE), `apex_verified: bool`, `ip_scope: [{cidr, class, action_set, confirmed_via}]`, `tos_version`, `signature`. No pipeline runs against a program without a valid, current authorization record (checked at enqueue time).

---

## 6. Modules — Roster & Phasing

Phase 1 must work for MVP. Phase 2 = differentiators. Phase 3 = expansion.

### Phase 1 — Core Pipeline
| # | Module | Tool [v2 choices] | Purpose |
|---|--------|------|---------|
| 1 | Recon — Subfinder | `subfinder` | Passive subdomain enum |
| 2 | Recon — crt.sh | HTTP | Certificate transparency |
| 3 | Recon — uncover | `uncover` | **[v2]** unifies Shodan/Censys/Fofa/Zoomeye behind one tool (replaces separate Shodan+Censys wrappers) |
| 4 | Recon — dnsx | `dnsx` | **[v2]** resolve, dedup, wildcard filter — feeds everything downstream |
| 5 | Probe — httpx | `httpx` | Alive check + tech fingerprint + title/status |
| 6 | Probe — TLS | `tlsx` | **[v2]** cert chain, expiry, SAN harvest (also a recon source) |
| 7 | Scan — Nuclei | `nuclei` (safe policy §9d) | Templated detection |
| 8 | Scan — Secret refs | `trufflehog`/`gitleaks` engine + JS analyzer | **[v2]** use maintained secret engines, not a hand-rolled "SecretFinder" |
| 9 | Crawl — Katana | `katana` (passive+active) | Endpoint discovery |
| 10 | Crawl — Archive URLs | `waybackurls`/`gau` | Historical URL harvest |

### Phase 2 — The Attacker's Edge
| # | Module | Tool | Purpose |
|---|--------|------|---------|
| 11 | Ports — naabu | `naabu` (rate-capped) | **[v2]** fast-but-polite port discovery; masscan disabled |
| 12 | Ports — Nmap NSE | `nmap` (`--max-rate` capped, safe scripts only) | Service/version ID on ports naabu found |
| 13 | Content — Feroxbuster | `feroxbuster` | Recursive directory discovery |
| 14 | Content — ffuf | `ffuf` | Parameter / vhost fuzzing |
| 15 | Content — Wordlist selector | native | Tech-aware wordlist chooser (WordPress→wp lists, etc.) |
| 16 | OSINT — GitHub leaks | GitHub API + gitleaks | Leaked-secret monitoring |
| 17 | OSINT — ASN mapper | `asnmap` | Org → ASN → netblocks (feeds §9b IP-scope confirmation) |
| 18 | OSINT — Cloud buckets | `cloudlist` + permutation | S3/Azure/GCP exposure |
| 19 | OSINT — Preview envs | native **[v2]** | Detect Vercel/Netlify/CF-Pages previews, `staging.`/`uat.`/`demo.` — the agency killer feature |
| 20 | Dork — search engines | Google CSE / Brave / SerpAPI (budgeted) | Indexed-exposure discovery |
| 21 | Intel — CVE/KEV feed | NVD + CISA KEV + GHSA | New-CVE→asset matcher w/ **confidence scoring [v2]** |
| 22 | Intel — Nuclei watch | git | New-template→asset matcher, state-aware re-run |
| 23 | Intel — Delta monitor | native | Detect asset change over time |
| 24 | Intel — Correlator | native | Chain findings across modules into one prioritized issue |

**CVE matcher (21) confidence policy [v2]:** version→CPE→CVE is noisy. Each match carries a `confidence` (version certainty × CPE-map certainty). Default: only `high` confidence alerts; **any CISA KEV match escalates to high regardless**; low/medium accumulate silently and surface in the UI, not as alerts. This single policy is what keeps false-positive rate under the credibility threshold.

### Phase 3 — Enterprise Expansion
Dalfox (XSS on crawled endpoints, opt-in, rate-limited), Nikto (server config), reporting (HTML/PDF/HackerOne/exec-summary), notification channels (Discord/Telegram/Slack/email/webhook), amass (heavy active enum, opt-in).

### 6b. Toolchain rationale (short)
ProjectDiscovery tools are Go, single-binary, JSON-output, rate-limit-flag-equipped, actively maintained, and designed to pipe into each other. Standardizing on them (`subfinder dnsx httpx naabu katana nuclei tlsx asnmap cloudlist uncover notify alterx`) shrinks the wrapper surface, gives consistent JSON parsing, and means one `nuclei -update-templates` cadence rather than a zoo of scanners. Non-PD tools kept because they're best-in-class: `feroxbuster`/`ffuf` (content discovery), `gau`/`waybackurls` (archives), `nmap` (deep service ID), `gitleaks`/`trufflehog` (secret detection). See ADR-0002.

---

## 7. Build Phases (Solo Dev, Part-Time — Logical Phases, Not a Calendar)

> These are **logical phases with mandatory exit gates**, not a 50-day schedule. Each is realistically **2–6 weeks of evening/weekend work**. Do not rush a phase exit. Do not take shortcuts that defer a §3 principle to "a later phase" — the principles are load-bearing from Phase A. Phase A→C is ~2–3 months part-time; A→G is realistically 8–12 months before a paying customer sees it.

**Phase A — Foundation.** `core/`, `db/`, `queue/` skeletons; Mongo + Redis connection and index bootstrap; `TenantScopedModel`; scope engine (`core/scope.py`) with unit tests for the deny-list; rate limiter; logging with context; config; `Dockerfile.pipeline` + `Dockerfile.worker` with every binary verified by `daemon/health.py`; Makefile (`dev test lint docker-build`).
*Exit:* `docker-compose up` starts api+worker+scheduler+mongo+redis. `python -m daemon.main --dry-run` prints the module registry and confirms every binary + the scope feeds loaded. `/healthz` returns 200. Scope engine unit tests prove RFC1918/metadata/CDN denial.

**Phase B — Core Pipeline (modules 1–10).** Each module: wrapper + pipeline + db layer + unit tests (mocked subprocess) + integration test against a target **you own** (not `example.com`/`hackerone.com` — see §8 note). Jobs flow through the queue, workers enforce scope+rate limits.
*Exit:* add a domain → scheduler enqueues ingest→probe→scan→crawl → findings land with correct `tenant_id`, `is_new=True`, dedup fingerprint, and lifecycle state `NEW`. Re-run is idempotent.

**Phase C — API + Auth.** FastAPI, JWT + API-key auth (keys stored SHA-256, shown once), tenant/program CRUD, findings read, **domain verification (DNS TXT + HTTP file)**, **authorization record creation with IP-scope confirmation [v2]**, per-tenant rate limiting (slowapi), websocket stream, OpenAPI at `/docs`.
*Exit:* curl flow: signup → verify email → create program → add domain → verify ownership → **authorization record created** → view first findings. All idempotent. Tenant-isolation test passes (tenant A cannot read tenant B with a valid JWT + guessed program_id).

**Phase D — Attacker's Edge (modules 11–24).** naabu with rate cap; content discovery selecting wordlist by fingerprint; CVE/KEV feed polling every 15 min, matching by CPE with confidence scoring, firing priority scans; delta monitor diffing alive assets (status/title-hash/tech/cert/new-port changes); preview-env detection.
*Exit:* push a new subdomain live at T=0 → first finding alert within target latency. Publish a KEV-listed CVE against a fingerprinted stack → matched-asset alert within target latency. naabu never exceeds the global rate cap (verified by metrics).

**Phase E — Frontend.** Next.js 14 + shadcn/ui + Tailwind, dark default. Screens in priority order: signup/login → overview → programs + add-program → domain-verification + authorization wizard → findings list (filters: severity/module/state/program) → finding detail (repro steps, matched CVE/KEV/EPSS) → asset inventory w/ fingerprint history → change timeline → reports → settings.
*Exit:* a new user signs up, adds a domain, verifies + authorizes it, and sees the first finding in the UI without support.

**Phase F — Notification + Reporting.** Per-tenant channel routing; severity thresholds and digest modes per channel; HTML/PDF/HackerOne/exec-summary reports. **Notifications never contain full secret values (§9c).**
*Exit:* finding → Discord within ~60s of DB insert; HackerOne-ready markdown generated from the UI.

**Phase G — Production Hardening.** Prometheus + Grafana; structured JSON logs; Sentry; encrypted Mongo backups; scope-feed auto-update job; rate-limit graceful degradation; deploy guides (DO/AWS/GCP/self-host); Helm chart.
*Exit:* runs 7 days unattended with real tenants and hundreds of domains, no intervention, no AUP complaints.

---

## 8. Testing

- **Unit:** every module, mocked subprocess. 80% coverage on `core/`, `db/`, `modules/`. `core/scope.py` gets exhaustive tests (every reserved range, metadata IP, CDN sample, exclusion list).
- **Integration:** every pipeline against a **target you legally control** and against deliberately-vulnerable, license-permitting targets. **[v2] Do not run active scans against `hackerone.com` or `example.com`** — you are not authorized to scan them, and it contradicts §9/§3.10. Use a self-owned test domain, `scanme.nmap.org` (nmap-sanctioned) for port tests, and local vulnerable apps (DVWA/Juice Shop) in the compose stack.
- **E2E:** signup → program CRUD → finding retrieval.
- **Load (Locust):** 100 tenants, 10k assets, 1M findings; API p99 < 500ms. Verify fair scheduling keeps a 5000-asset tenant from starving others.
- **Security:** tenant isolation, NoSQL injection on every route, JWT tampering, **scope-bypass attempt** (prove no module reaches the network without `assert_in_scope`), **secret-leak-in-notification** test.

---

## 9. Security, Compliance & Legal

Baseline (unchanged, all required): secrets in env only, never in code or Docker layers; API keys stored SHA-256, raw shown once; JWT HS256 with rotating secret + refresh tokens; **rate limits per tenant**; CORS locked to frontend domain in prod; CSP with no inline scripts; Trivy image scans in CI; audit log for every write (tenant_id, actor_id, timestamp, diff); retention (findings 2y, raw scan output 90d — **raw exposed-secret evidence 30d, §9c**); ToS states the customer authorizes scanning of domains they add, Vantari stays in scope, detection-only.

### 9b. Scanning authorization scope [v2]
DNS-TXT/HTTP-file verification proves apex control — **not** authorization to aggressively scan every IP a subdomain resolves to. Before active work on any resolved IP:
1. `core/scope.classify_ip` labels it `DEDICATED | CDN | CLOUD_SHARED | ...`.
2. **`CDN`/`CLOUD_SHARED` → HTTP-layer probing only** (httpx, safe passive nuclei tags). No port scan, no aggressive templates, no content bruteforce — that infrastructure belongs to Cloudflare/AWS/etc., not the customer.
3. **`DEDICATED` → full scan**, where "dedicated" is confirmed by WHOIS/ASN ownership matching the customer's verified org (via `asnmap`), recorded in the authorization record (§5d).
4. Everything is gated on a current authorization record; enqueue refuses without one.

### 9c. Exposed-secret handling [v2] — do not become a honeypot
When Vantari finds a customer's leaked secret (`.env`, key in JS, GitHub leak), storing the plaintext makes Vantari's DB a high-value target holding *other companies'* live credentials. Policy:
- Store a **masked** value (e.g., `AKIA••••••••7Q`), a **keyed hash** (for dedup, never reversible to plaintext), and a **locator** (URL/file/line).
- Any retained raw snippet is **encrypted at rest** (envelope encryption; app-tier key separate from DB).
- **Raw evidence retention ≤ 30 days**, then purged to masked+hash only.
- **Notifications never contain the full secret** — masked value + locator + "rotate this now."
- Findings UI reveals full value only to authorized tenant users, over an audited, time-boxed action.

### 9d. Nuclei safe-template policy & the detection/exploitation line [v2]
- Run with **`-etags dos,intrusive,fuzz`** excluded for continuous scanning. Those tags contain templates that send heavy or state-changing payloads.
- Pin the template set to a reviewed commit; the Nuclei-watch module (module 22) proposes new templates, which are reviewed before promotion.
- Aggressive/opt-in modules (Dalfox, ffuf fuzzing) run only with explicit per-program opt-in, under the global rate cap, and never against CDN/cloud-shared IPs.
- The enforceable definition of "detection only": **no payload that modifies target state, causes DoS, or exfiltrates data beyond a minimal benign proof.** This is both code policy and a term of service.

### 9e. Legal posture
Per-program authorization record (§5d) with stored ToS version + actor + timestamp is the CFAA/CMA/Computer-Misuse defensibility artifact. Scanning without it is refused at enqueue. Document the platform's egress IPs and keep abuse-contact handling ready before Masscan or any high-rate scanning is ever enabled.

---

## 10. Documentation
`README.md` (5-min `docker-compose up` quickstart) · `docs/ARCHITECTURE.md` (this doc, condensed) · `docs/ADRs/` (one per non-obvious decision; ADR-0001 MongoDB, ADR-0002 PD toolchain, ADR-0003 task queue, ADR-0004 masscan-disabled, ADR-0005 scope engine, ADR-0006 secret handling) · `docs/API.md` (from OpenAPI) · `docs/DEPLOYMENT.md` (DO/AWS/GCP/self-host) · `docs/SECURITY.md` (threat model, tenant-isolation guarantees, scope-enforcement guarantees, secret-handling posture). Docstrings on every public function.

---

## 11. Coding Standards
Python 3.11+, type hints on every signature, `mypy --strict` in CI. `ruff` (lint+format). Pydantic v2. `loguru` (never `print`). `motor` (never sync PyMongo in async paths). `aiohttp` (never `requests` in async). Every tool wrapper handles `FileNotFoundError`, `TimeoutError`, `OutOfScope`, `RateLimited`, and generic exceptions with structured logging and explicit return values. Every subprocess: timeout + hard kill. Every DB write: `$setOnInsert` + `$set`. **Every network module: `await assert_in_scope(...)` before I/O.** No `TODO` in main — track in issues.

---

## 12. Cross-Platform via Containers
No native install on Windows/macOS. Pipeline runs in the Alpine/Debian-slim image on Linux, macOS (Docker Desktop), Windows (WSL2). API/frontend run natively or containerized. `docker-compose up` gives the full stack (api, worker, scheduler, mongo, redis, frontend). Production is Kubernetes-native (Helm chart) or plain Compose for small deployments.

---

## 13. Commercial Model (architecture must support, not built now)
Free (1 domain, 30-day retention, community notifications), Professional $99/mo (5 domains, 1y, all channels, HackerOne export), Business $499/mo (25 domains, 2y, priority queue, custom webhooks, SSO), Enterprise (unlimited, on-prem option, dedicated scan infra, SLA, audit export). **Plan limits are checked at enqueue** (before a scan consumes resources), and plan changes take effect immediately. Commercial API calls (uncover backends, SerpAPI, etc.) are metered per tenant against plan budget.

---

## 14. Explicit Non-Goals (v1)
No internal network scanning; no endpoint detection; no SIEM/log aggregation; **no exploitation/PoC execution (§3.10, §9d)**; no managed pentest service; no user-authored Nuclei templates (v1.1); no dark-web monitoring (v2); no threat-actor attribution (v2). **[v2] No masscan / no high-rate scanning until dedicated netblocks exist.**

---

## 15. Success Metrics (instrument from day one)
Time to first finding (signup→first alert, target <15 min) · Alert precision (user-marked false-positive rate, target <5% — the make-or-break metric) · New-asset detection latency (target <30 min) · CVE/KEV match latency (target <60 min) · Weekly active domains · **[v2] AUP-complaint count (target 0)** · **[v2] p95 target request rate stays ≤ configured cap**.

---

## 16. What "Done" Looks Like
A prospect signs up, verifies email, adds `their-company.com`, verifies ownership via DNS TXT, confirms the authorization record, and within ~15 minutes sees discovered subdomains, alive endpoints with tech labels, findings ranked by severity each with a reproduction command, and receives the first Discord alert (`.env` exposed at `staging.their-company.com`, masked value + "rotate now"), with a live-updating finding list. The next afternoon their team pushes `demo-new.their-company.com`; minutes later Vantari has it, and shortly after the security team is alerted that it runs an outdated stack with a KEV-listed vuln.

---

## 17. Architecture Decision Records
Any deviation or non-obvious choice gets `docs/ADRs/NNNN-title.md`:
```
# NNNN — Title
Date: YYYY-MM-DD
Status: Accepted | Superseded | Deprecated
Context / Decision / Consequences / Alternatives considered
```
Seed ADRs to write in Phase A: **0001** MongoDB over Postgres+JSONB (flexible finding schemas, team familiarity; note Postgres wins on transactions/joins — revisit at scale) · **0002** ProjectDiscovery-first toolchain · **0003** Redis+arq task queue over async-loop daemon · **0004** Masscan disabled in v1 (AUP/termination risk) · **0005** Central scope engine · **0006** Exposed-secret masking/encryption.

---

## 18. First-Session Instructions (for Claude Code)
1. Read this entire document.
2. Summarize the phases back in ~200 words to confirm understanding.
3. Ask **one** clarifying question only if something is genuinely ambiguous; otherwise begin Phase A.
4. Create the §4 directory structure.
5. Initialize `pyproject.toml`, `.env.example`, `Makefile`, `docker-compose.yml` (api, worker, scheduler, mongo, redis, frontend).
6. Write `core/config.py`, `core/logging.py`, `core/models.py` (base + tenant), **`core/scope.py` + `core/ratelimit.py` with tests first — they are load-bearing.**
7. Write `db/mongo.py` (connection + index bootstrap).
8. Write `Dockerfile.pipeline` + `Dockerfile.worker` with every §6 binary installed (masscan present but flag-disabled) and verified by `daemon/health.py` (binaries + Mongo + Redis + config + scope feeds).
9. Write `daemon/health.py`.
10. Commit. Move to Phase B.

Do not build the frontend before Phase E. Do not build reporting before Phase F. Do not skip tests. Do not let a network module touch the wire without the scope engine.

---
**End of prompt. Build the platform. Detection only. Stay in scope. Do the work.**
