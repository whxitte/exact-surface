# ExactSurface

**Continuous external attack-surface intelligence — detection only.**

ExactSurface continuously answers one question for every domain a customer owns:
*"What does an external attacker see right now, and what can they do with it?"*
It runs the tooling real attackers use (subfinder, httpx, nuclei, katana, naabu,
wordlist fuzzing), is state-aware (one alert per genuinely new fact, not per
re-scan), multi-tenant from line one, and **never exploits — only detects**.

### Documentation map

| Read this | For |
|---|---|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | **start here** — the loop, layers, the five control points, data model, known gaps |
| [`docs/SECURITY.md`](docs/SECURITY.md) | the control model: authorisation chain, scope enforcement, tenant isolation, politeness/AUP, secret handling |
| [`docs/API.md`](docs/API.md) | endpoint reference + the rules a schema can't show (why cross-tenant is 404, why `ip_scope` is strings) |
| [`docs/ADRs/`](docs/ADRs/) | why things are the way they are — read before changing a control |
| [`docs/TESTING.md`](docs/TESTING.md) | run it end-to-end against a target you own (quick) |
| [`docs/PRICING_AND_LIMITS.md`](docs/PRICING_AND_LIMITS.md) | **capabilities & limits** — full free self-hosted edition details (unlimited domains, users, scans, and modules) |
| [`deploy/README.md`](deploy/README.md) | **what a customer receives** — the self-contained deployment folder: what comes up, configuration, troubleshooting. Copied verbatim into the release archive |
| [`docs/LICENSING.md`](docs/LICENSING.md) | details of the free, unrestricted self-hosted deployment architecture |
| [`docs/OWNER_RUNBOOK.md`](docs/OWNER_RUNBOOK.md) | **for you, the owner** — cutting a release, customer delivery, doing a dry run |
| [`demo/README.md`](demo/README.md) | **the public demo site** — a separate, static, backend-free build of the real frontend; how it is deployed (Docker or Vercel) and how it stays out of product images |
| [`website/README.md`](website/README.md) | **the marketing site** — static HTML, zero build step, deploy-to-Vercel instructions |
| [`docs/DEVTOOLS.md`](docs/DEVTOOLS.md) | **the Workbench** — the internal module test bench: why it is a separate app, how it is contained, how to use it |
| [`docs/TESTING_GUIDE.md`](docs/TESTING_GUIDE.md) | **full test coverage** — the 7 layers, what to test when, security/safety verification |
| [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) | roles, images, sizing, observability (scraping only the api shows you nothing about scanning) |
| [`EXACTSURFACE_BUILD_SPEC.md`](EXACTSURFACE_BUILD_SPEC.md) | the full original design spec (authoritative) |
| [`context.md`](context.md) | running engineering log: what's done, what's known-broken, and why |

New to the codebase? `ARCHITECTURE.md` → `SECURITY.md` §2 (why domain control ≠
scanning authorisation) → ADR-0005 and ADR-0008. Those explain the constraints
that shape everything else.


## What lives in this repo

Four applications. Only the first is shipped to customers.

| | What | Who runs it | Built from |
|---|---|---|---|
| **The product** | api + frontend + pipeline images, run from `deploy/` | **the customer**, self-hosted | `docker/Dockerfile.{api,frontend,pipeline}` |
| **The demo** | a static, backend-free build of the real frontend | you, at `demo.exactsurface.com` | `demo/Dockerfile` (or Vercel, see `demo/README.md`) |
| **The marketing site** | static HTML, no build step | you, at `exactsurface.com` | `website/` (Vercel, see `website/README.md`) |
| **The workbench** | internal module test bench | you, on your laptop only | `devtools/`, never containerised |

**They cannot mix.** The product Dockerfiles copy named directories only — never
`COPY . .` — so `demo/`, `website/` and `devtools/` are never in the build context of
any customer image. `.dockerignore` excludes all three, `demo/Dockerfile.dockerignore`
excludes every backend directory from the demo's own context, and
`tests/unit/test_wiring.py` fails the build if any of that is undone. Verified against
real images, not just asserted.

## Status

**v1.0.0 is released and has run a real, unattended full scan against real
infrastructure end to end. The customer install path exists, works, and has been
run — by the owner, not yet by an outside customer.**

| Area | State |
|------|-------|
| Core (scope engine, fingerprints, severity, lifecycle, plans, signal) | ✅ built + exhaustively unit-tested |
| Politeness limiter — fleet-shared (Redis) + degrading, wired into every scan | ✅ (ADR-0012); every scanner subprocess rate-capped (ADR-0013) |
| Modules + pipelines (recon → probe → crawl → scan → secrets → CVE → notify) | ✅ 28 modules, all reachable, all mentioned in the in-app Knowledge page |
| Scheduler + worker execution (arq), cascade, cadence, fairness cap | ✅ run unattended against a real domain (see below) |
| API — auth, tenant isolation, RBAC; Next.js dashboard | ✅ (security suite in `tests/security/`) |
| Observability — Prometheus/Grafana, Sentry, per-process `/metrics` | ✅ (ADR-0011) |
| Encrypted Mongo backups, scope-feed auto-update, prod compose | ✅ (ADR-0014) |
| Customer install (`deploy/` bundle) | ✅ built, documented, run end to end by the owner |
| Unit + integration + security tests | ✅ 929 passing, ruff + tsc clean |

**What has actually been run, not just tested against fakes:**

- A full unattended scan against a real domain, real subdomains, real live hosts —
  discover → probe → crawl → content-discovery → vuln scan → secrets → CVE watch →
  correlate → notify, all 28 modules, reading the real logs line by line afterward
  rather than trusting a green summary.
- Verified continuous 28-module pipeline execution and unrestricted self-hosted deployment flow.
- A release built, published to GHCR, pulled fresh, and verified from the published
  artifact alone — not a local build.
- The `deploy/` bundle, unpacked and started on a clean project directory the way a
  customer's first `docker compose up -d` would go.

**What genuinely has not been run:**

- **A clean-machine customer dry run** — the bundle installed by someone who is not
  the owner, on a machine that has never touched this repo. This is the highest-value
  remaining validation step; see `context.md`'s session-close note.
- **The §7 exit gate** — 7 days unattended with real (multiple) tenants.
- **No load test** yet (§8: 100 tenants / 10k assets / 1M findings, p99 < 500ms).
- **No backup has ever been restored** — only taken.
- **CVE/KEV match latency (§15)** is not measurable — `CveRecord` lacks a
  `published` timestamp.

> A recurring lesson from the engineering log, still true: the failures worth
> worrying about are not the ones a green test suite catches. Every serious bug this
> project has shipped — a dispatch route missing, a scope-feed file never committed,
> a compose project-name collision that
> could silently destroy a running deployment — was found by *using* the product on
> real infrastructure, never by reading the code or running the unit suite. Treat
> "tests pass" as necessary, not sufficient.

## Quickstart (full stack, any OS)

```bash
cp .env.example .env         # then edit secrets before prod
docker compose -f docker/docker-compose.yml up --build
# API:     http://localhost:8000/healthz  ->  {"status":"ok"}
# Docs:    http://localhost:8000/docs
```

## Local dev (without Docker)

```bash
make venv && make install          # create .venv, install deps
make test                          # run the unit suite
make dry-run                       # health checks + module registry, no network
make api                           # run the API on :8000
make lint                          # ruff
```

`make dry-run` prints the module registry and validates config, scope feeds, every
required binary, Mongo, and Redis. Config + scope-feed checks are the hard gate;
binary/DB checks pass inside the pipeline image.

## Architecture in one breath

A **scheduler** reads state and enqueues jobs onto a **Redis (arq)** queue.
Stateless **workers** (the pipeline Docker image, with all recon tools) pull jobs,
and for each target: confirm a current **authorization record**, resolve it, get a
**scope decision**, and run the module within its permitted action set — under a
global **politeness rate cap**. Results upsert into **MongoDB** by content-hash
fingerprint (idempotent, state-aware). New/changed facts fan out to
**notifications**.

## Safety & compliance (non-negotiable)

- **Central scope engine** denies internal/metadata/CDN/out-of-scope targets by
  construction (ADR-0005).
- **Masscan disabled in v1**; naabu rate-capped (ADR-0004).
- **CDN/cloud-shared IPs get HTTP-layer probing only** — full scans require
  confirmed-dedicated ownership.
- **Exposed secrets are never stored in plaintext** (ADR-0006).
- **Detection only** — nuclei runs with `dos,intrusive,fuzz` excluded.

---
### Local testing - clean everything and fresh start guide:

1 · Complete wipe
From the repo root:

```bash
docker compose -f docker/docker-compose.yml down -v
```

The -v is the important part — it deletes the named volumes (mongo_data, redis_data, grafana_data, …), so every tenant, program (example.com + your other one), finding, and scan is gone. Containers and networks go too.

(Optional, if you also changed code and want an image rebuild from scratch: add --rmi local.)

2 · Brand-new up

```bash
docker compose -f docker/docker-compose.yml up --build -d
docker compose -f docker/docker-compose.yml ps        # wait until mongo/redis are "healthy"
```
--build rebuilds the images so any code changes are in. Give it ~30–60s.

3 · Sign up + add the program (UI)
Open http://localhost:3000 →

Create account (this makes your fresh tenant + user).
Go to Programs → add quipohealth.com.
Stop there — don't try to verify in the UI. (Email verification is off in dev by default, so signup + add-program won't be blocked. If your .env set EXACTSURFACE_REQUIRE_EMAIL_VERIFICATION=true, the verification link is printed in the API logs: docker compose -f docker/docker-compose.yml logs api | grep verify.)

4 · Bypass DNS verification (one command)

```bash
docker compose -f docker/docker-compose.yml exec api python - <<'PY'
import asyncio
from db.mongo import get_mongo
from db.programs import ProgramRepo
from db.authorizations import AuthorizationRepo
from core.models import Authorization

async def main():
    m = get_mongo(); await m.connect()
    progs = await ProgramRepo.from_mongo(m).list_all()
    match = [p for p in progs if p["apex_domain"] == "quipohealth.com"]
    if not match:
        print("!! add quipohealth.com in the UI first"); return
    p = match[0]; tid, pid = p["tenant_id"], p["program_id"]
    await ProgramRepo.from_mongo(m).set_verified(tid, pid, True)
    await AuthorizationRepo.from_mongo(m).save(Authorization(
        tenant_id=tid, program_id=pid, authorized_by="dev-bypass", apex_verified=True))
    print(f"OK — {pid} is now verified + authorized")

asyncio.run(main())
PY
```
This flips the program to verified and writes a current authorization (apex_verified=True) — exactly what steps 3–5 of the normal flow would produce, minus the DNS TXT check. It runs inside the api container, so the model shapes are guaranteed correct:

You should see OK — prog_xxxx is now verified + authorized.

5 · Start the scan
Reload the program in the UI — it now shows Verified. Either:

Click Scan (the /scan trigger), or
Just wait — the scheduler's bootstrap tick will enqueue the first full run automatically (a program that's never completed a run is "due immediately").
6 · Watch it
UI → Activity tab, or the logs: docker compose -f docker/docker-compose.yml logs -f worker
Then check Assets (interest badges), Findings, Endpoints (risk tags).
Two things to expect, so they don't look like bugs:

Port scanning and content-discovery will likely skip with a note like "no confirmed-dedicated hosts." That's correct — those only run on IPs confirmed as yours via asnmap (§9b), which the DNS bypass doesn't do. Probe, crawl, nuclei (safe), and secrets will all run over HTTP. If you want port scans against your own infra, set scan_shared_infra=true on the program (add await ProgramRepo.from_mongo(m).save(...) or a Mongo update) — but only because you own it.
This is a real scan hitting quipohealth.com over the network, rate-limited to 10 req/s per target. Fine, since it's your domain.
⚠️ One honest caveat: only ever do this bypass for a domain you actually own, on your own instance. Domain verification is the control that keeps ExactSurface from scanning someone else's property — bypassing it for a domain you don't control is exactly the AUP/legal violation the whole authorization chain exists to prevent. quipohealth.com is yours, so you're clear.

It's posible to set  a quick mongosh one-liner to flip scan_shared_infra on (so this run includes port + content-discovery against our own infra)

---

Email — why/what/where? It's for signup email verification only (the confirm-your-address link), and it's config, not a UI setting — that's why you don't see it in the app. In dev, EXACTSURFACE_EMAIL_TRANSPORT=log just prints the link to the API logs (no provider needed). To send real mail, set smtp + any provider's SMTP creds in .env. "Provider-agnostic" means it speaks plain SMTP, so Resend/Brevo/SES all work. Nothing to configure to test scanning.

Tech-aware nuclei — will it lose generic findings (expired TLS, etc.)? No. The safe baseline is still exposure, misconfig, tech, ssl, cve, default-login — TLS/expiry, generic misconfigs, CVEs all still run. The tech tags are added on top (a WordPress host also gets WordPress templates). It's strictly more coverage, never less, on the safe scan. Only the aggressive run (confirmed-dedicated infra) uses the full library.

Where's the ASN mapper in the pipeline? It's not a visible stage — it runs inside authorization confirmation (confirm_authorization_ip_scope, before scanning), which is why it's not in the stepper. It's the mechanism that answers your next question:

How is the "point x.mydomain.com at any IP, declare /24 dedicated, scan third-party infra" risk prevented? The client only ever requests CIDRs — they're recorded as unconfirmed (HTTP-layer only). Before each scan, the worker runs asnmap on your verified apex's real announced ASN and promotes a CIDR to dedicated only if it actually falls in that ASN's ranges. Self-attestation never unlocks aggressive scanning. That's exactly why you saw "no confirmed-dedicated hosts — ports/content withheld (§9b)" — quipohealth.com is on shared/cloud infra, so port scan + content discovery + active nuclei were correctly withheld. To scan your own cloud infra, flip the "Scan my cloud infra" toggle (scan_shared_infra) — only because you own it.

What is nuclei_watch? It baselines which nuclei templates currently match your stack, then alerts when a NEW template starts matching (e.g. a fresh CVE template now fires on your host). It's opt-in because its template-lister contract is unverified against the pinned binary.

Grafana — creds/config? http://localhost:3001, login admin / admin in dev (set GRAFANA_ADMIN_PASSWORD to change). Nothing to configure — the Prometheus datasource and the "ExactSurface — Operations" dashboard are auto-provisioned. Panels populate during a scan (worker/scheduler are scraped on :9100).

## Scan modules

The pipeline mirrors a real black-box engagement, in order:

| Module | What it does |
|---|---|
| Domain intelligence | Email spoofability (SPF/DMARC/DKIM) + registration risk (expiry, transfer lock, DNSSEC). Fully passive. |
| Subdomain discovery | subfinder + crt.sh + DNS, plus **alterx permutations** (only names DNS confirms are kept). *Required.* |
| **Cloud asset inventory** | Asks your own AWS/GCP/Azure/DigitalOcean accounts what they run, finding assets no DNS name points at. Read-only credentials stay in your deployment. Opt-in. |
| Internet-index search | Shodan/Censys/Fofa via uncover. Opt-in. |
| **Reverse-DNS sweep** | PTR-sweeps IP ranges confirmed yours, finding hosts that exist in IP space but were never published in DNS. Opt-in; only runs on ASN-verified ranges and refuses anything wider than a /20. |
| Live-host probing | httpx — alive check + technology fingerprint. *Required.* |
| TLS inspection | Certificate expiry and weak configuration. Opt-in. |
| Subdomain takeover | Dangling DNS pointing at claimable cloud services. |
| Crawling & archives | katana + gau/waybackurls. |
| Content discovery | feroxbuster (ffuf fallback), tech-aware wordlists. |
| **JavaScript mining** | Mines your own JS bundles for API routes, internal hostnames and source maps; discovered paths feed back as endpoints. |
| **API & path disclosure** | robots.txt + sitemap mining, OpenAPI/Swagger schema detection, GraphQL introspection, `.well-known`. Paths found become endpoints. |
| **CORS, redirects & WAF** | Reflected/null-origin CORS with credentials, open redirects (only on parameters the site already uses), and which hosts sit behind a WAF. |
| **Hidden parameters** | Inventories the query parameters your pages already use (free), and probes a curated list for undocumented ones that change behaviour. Opt-in. |
| **Broken-link hijacking** | Outbound links to unregistered domains or unclaimed social handles. |
| Port scanning | naabu, on confirmed-dedicated infrastructure only. |
| Service fingerprinting | nmap -sV. Opt-in. |
| Vulnerability scanning | Full nuclei corpus, tech-targeted. |
| Exposed secrets | Page/script bodies scanned for keys and tokens (masked, never stored raw). |
| CVE watch | NVD + CISA KEV matched to fingerprinted software. |
| Public code leaks | GitHub code search for secrets tied to the domain. |
| Cloud storage exposure | S3/GCS/Azure bucket enumeration. Opt-in. |
| New-template watch | Alerts when a newly published nuclei template starts matching your stack. Opt-in. |
| Search-engine exposure | Dorking. Opt-in (needs a search API key). |
| **Dependency confusion** | Internal package names in your public JS that nobody has claimed on npm — an attacker who publishes one lands code in your build. |
| **Lookalike domains** | Registered typosquats aimed at phishing your staff and customers; MX records rank higher. Opt-in (resolves ~600 names per run). |
| Risk correlation | Groups findings per host into ranked attack chains, and retells them as an **attack path** in attacker order (needs 2+ phases on one host — a single finding is never called a chain). |
| Alerting | Delivers new findings to your channels. |

On-demand (not scheduled): **403/401 bypass** — from the Endpoints tab.

Every module can be turned on or off per program, and each has its own re-run cadence.
Modules depend on each other, so disabling one also stops what consumes its output —
the UI states this before you confirm. Subdomain discovery and live-host probing are
required and cannot be disabled.

