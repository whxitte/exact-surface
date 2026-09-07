# ExactSurface

**Continuous external attack-surface intelligence — detection only, self-hosted, open source.**

ExactSurface answers one question, continuously, for every domain you own:
*"What does an external attacker see right now, and what can they do with it?"*

It runs the tooling real attackers use (subfinder, httpx, nuclei, katana, naabu,
feroxbuster, and more), is **state-aware** — one alert per genuinely new fact, not one
per re-scan — multi-tenant from line one, and **never exploits, only detects**.

| | |
|---|---|
| **Live demo** | [exactsurface-demo.vercel.app](https://exactsurface-demo.vercel.app) — the real frontend against seeded output from a real scan. No backend, nothing to sign up for. |
| **Project site** | [whxitte.github.io/exact-surface](https://whxitte.github.io/exact-surface) — built from the `site` branch |
| **Licence** | Apache-2.0 |
| **Current release** | 1.2.0 |

---

## ⚠️ Authorised use only

ExactSurface actively probes hosts over the network. Point it only at infrastructure
you own or have **written permission** to test. Unauthorised scanning is illegal in
most jurisdictions regardless of intent, and "I was only enumerating" is not a defence.

The product is built so that this is hard to get wrong by accident:

- A program cannot be scanned until its apex domain passes **DNS TXT verification**,
  proving you control it.
- A **central scope engine** refuses internal, metadata, CDN and out-of-scope addresses
  by construction, not by a checklist someone remembers to apply (ADR-0005). One
  per-program switch, **off by default**, waives it — see *Scope override* below.
- Aggressive actions (port scanning, content discovery, the full nuclei corpus) require
  IP ranges **confirmed** yours via ASN lookup. Self-attestation never unlocks them —
  declaring a `/24` you do not own gets you HTTP-layer probing and nothing more (§9b).
- nuclei runs with `dos,intrusive,fuzz` excluded. There is no exploitation path in this
  codebase, and pull requests adding one will not be merged.

Those controls are the point of the project, not paperwork around it. If you are about
to work around one, read [`docs/SECURITY.md`](docs/SECURITY.md) §2 first.

### Scope override

A program setting — **off by default** — that waives the scope engine for that domain:
scans may then reach hosts outside it, internal and loopback ranges, and third-party CDN
edges, with the full action set on all of them.

It exists because the engine decides scope from what it can *prove*, and an operator
sometimes owns infrastructure it cannot prove: hosts behind a CDN, an internal range, a
cloud block the ASN check will not confirm. Withholding port scanning there is the right
default and the wrong answer for someone scanning their own estate.

It does not waive: your own host and CIDR exclusion lists, the politeness rate cap, the
requirement that a program be verified and authorized to scan at all, or the link-local
block. It changes what a scan may *reach*, never whether it was allowed to run, and every
flip is logged.

**It can reach beyond your own estate** — a CDN edge is shared with that provider's other
customers — so turn it on only where you are authorised to scan everything the domain
resolves to. It deliberately cannot reach `169.254.169.254`: that is the metadata service
of the host running the worker, not anything belonging to the target.

---

## Quickstart

### Run the stack locally

```bash
git clone https://github.com/whxitte/exact-surface.git && cd exact-surface
cp .env.example .env         # edit the secrets before anything reachable
docker compose -f docker/docker-compose.yml up --build
```

- Dashboard → http://localhost:3000
- API health → http://localhost:8000/healthz → `{"status":"ok"}`
- API docs → http://localhost:8000/docs
- Grafana → http://localhost:3001 (`admin` / `admin` in dev)

Then sign up in the UI — **the first account created becomes the instance owner** —
add a domain you control, and complete DNS verification.

### Deploy it for real

[`deploy/`](deploy/) is a self-contained folder: compose file, Caddy for automatic TLS,
`.env.example`, and backups. It pulls published images rather than building.

```bash
cd deploy && cp .env.example .env   # set DOMAIN and the datastore secrets
docker compose up -d
```

Read [`deploy/README.md`](deploy/README.md) first — it covers sizing, what comes up, and
the failure modes worth recognising.

### Develop without Docker

```bash
make venv && make install    # .venv + dependencies
make dry-run                 # config, scope feeds, binaries, Mongo, Redis — no network
make test                    # the suite (1022 tests)
make api                     # API on :8000
make lint                    # ruff
```

`make dry-run` is the honest health check: it prints the module registry and validates
config, scope feeds, every required binary, and both datastores. The config and
scope-feed checks are a hard gate; binary and DB checks pass inside the pipeline image.

---

## What it does

The pipeline mirrors a real black-box engagement, in order. Every module can be toggled
per program and has its own re-run cadence; modules depend on each other, so disabling
one also stops whatever consumes its output — the UI says so before you confirm.
Subdomain discovery and live-host probing are required and cannot be disabled.

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
| **Lookalike domains** | Registered typosquats aimed at phishing your staff and operators; MX records rank higher. Opt-in (resolves ~600 names per run). |
| Risk correlation | Groups findings per host into ranked attack chains, and retells them as an **attack path** in attacker order (needs 2+ phases on one host — a single finding is never called a chain). |
| Alerting | Delivers new findings to your channels. |

On-demand, from the Endpoints tab: **403/401 bypass**.

## The Playground

`/playground` is an n8n-style canvas for running the same modules by hand: drag nodes
out of a palette, set their parameters, wire one node's output into another's input, and
run it. 36 nodes — 28 pipeline modules, 6 utility transforms, a target source and an
output viewer.

It is deliberately **not** a second execution engine. The dataflow edge already existed
and was simply invisible: `taskqueue/cascade.py` held a graph of *phase → downstream
phases*, every recon pipeline already returned the hosts it found as
`result["cascade_targets"]`, and dispatch already accepted `targets=(...)`. The canvas
exposes that pair and lets you rewire it, executing through the same dispatch table a
scheduled scan uses — so the two cannot drift apart.

Two tiers, built differently on purpose:

- **Pipeline nodes** are *derived* from the module registry, so a new module appears on
  the canvas the moment it is registered, and a wiring test fails if it does not.
- **Utility nodes** are a hand-written allow-list, deliberately not introspection. The
  local-only workbench can reflect over every callable under `modules/`; the same trick
  behind a product API would let a saved workflow name any importable function and hand
  it arguments. A test asserts `core/playground.py` contains no `getattr(`,
  `importlib.import_module(`, `eval(` or `exec(`.

Runs execute on the worker, where the scanning toolchain lives, and report progress per
node onto the canvas.

## Architecture in one breath

A **scheduler** reads state and enqueues jobs onto a **Redis (arq)** queue. Stateless
**workers** — the pipeline image, with all the recon tools — pull jobs and, for each
target: confirm a current **authorization record**, resolve it, get a **scope decision**,
and run the module within its permitted action set, under a global **politeness rate
cap**. Results upsert into **MongoDB** by content-hash fingerprint, which is what makes
re-scans idempotent and alerts state-aware. New or changed facts fan out to
**notifications**.

## What lives in this repo

Three applications on this branch. Only the first is what you deploy — the project
site lives on the `site` branch, which carries nothing else.

| | What | Who runs it | Built from |
|---|---|---|---|
| **The product** | api + frontend + pipeline images, run from `deploy/` | you, self-hosted | `docker/Dockerfile.{api,frontend,pipeline}` |
| **The demo** | a static, backend-free build of the real frontend | the maintainer, on Vercel | `demo/Dockerfile` (or Vercel — see `demo/README.md`) |
| **The workbench** | internal module test bench | contributors, locally only | `devtools/`, never containerised |

**They cannot mix.** The product Dockerfiles copy named directories only — never
`COPY . .` — so `demo/` and `devtools/` never enter the build context of a product
image. `.dockerignore` excludes them, `demo/Dockerfile.dockerignore`
excludes every backend directory from the demo's own context, and
`tests/unit/test_wiring.py` fails the build if any of that is undone. Verified against
real images, not merely asserted.

## Documentation

| Read this | For |
|---|---|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | **start here** — the loop, the layers, the five control points, the data model, known gaps |
| [`docs/SECURITY.md`](docs/SECURITY.md) | the control model: authorisation chain, scope enforcement, tenant isolation, politeness/AUP, secret handling |
| [`docs/API.md`](docs/API.md) | endpoint reference, plus the rules a schema cannot show (why cross-tenant is 404, why `ip_scope` is strings) |
| [`docs/ADRs/`](docs/ADRs/) | why things are the way they are — read before changing a control |
| [`docs/TESTING.md`](docs/TESTING.md) | running it end-to-end against a target you own |
| [`docs/FAQ.md`](docs/FAQ.md) | resetting a local instance, and the questions that keep coming up |
| [`docs/TESTING_GUIDE.md`](docs/TESTING_GUIDE.md) | the seven test layers — what to test when, and how safety is verified |
| [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) | roles, images, sizing, observability (scraping only the API tells you nothing about scanning) |
| [`deploy/README.md`](deploy/README.md) | the deployment folder itself: what comes up, configuration, troubleshooting |
| [`docs/DEVTOOLS.md`](docs/DEVTOOLS.md) | the Workbench — why it is a separate app and how it is contained |
| [`docs/OPERATIONS.md`](docs/OPERATIONS.md) | running it in production: requirements, install, backups, upgrades, scaling |
| [`docs/RELEASING.md`](docs/RELEASING.md) | cutting a release |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | the biggest gaps, and where to start if you want to close one |
| [`CHANGELOG.md`](CHANGELOG.md) | what changed in each version |

New here? `ARCHITECTURE.md` → `SECURITY.md` §2 (why domain control ≠ scanning
authorisation) → ADR-0005 and ADR-0008. Those explain the constraints that shape
everything else.

## Releases

Current release **1.2.0**. See [`CHANGELOG.md`](CHANGELOG.md) for what changed in each
version, and the [releases page](https://github.com/whxitte/exact-surface/releases) for
image digests and the packaged `deploy/` bundle.

> A recurring lesson from building this, worth stating once: the failures worth worrying
> about are not the ones a green test suite catches. Every serious bug this project has
> shipped — a dispatch route missing, a scope-feed file never committed, a compose
> project-name collision that could silently destroy a running deployment, a published
> image whose dependencies a `.dockerignore` rule had quietly stripped — was found by
> *using* the product, never by reading the code or running the unit suite. Treat "tests
> pass" as necessary, not sufficient.

## Contributing

Issues and pull requests are welcome — see [`CONTRIBUTING.md`](CONTRIBUTING.md). Two
things to know first: **the safety controls are not negotiable** (detection only; a
change that weakens the scope engine, the politeness cap or the §9b authorization gate
needs an ADR arguing the case), and **registries must not drift** — a module lives in
seven places, and `tests/unit/test_wiring.py` fails naming whichever one you missed.

Found a security bug? Report it privately: [`SECURITY.md`](SECURITY.md).

## Licence

Apache-2.0 — see [`LICENSE`](LICENSE). You may use, modify and redistribute
ExactSurface, including commercially and in closed-source products, subject to the
attribution and patent terms in the licence.

The bundled scanning tools (subfinder, httpx, nuclei, katana, naabu, feroxbuster, nmap
and others) are third-party software under their own licences, downloaded into the
pipeline image at build time and not redistributed as part of this repository.
