# Vantari

**Continuous external attack-surface intelligence — detection only.**

Vantari continuously answers one question for every domain a customer owns:
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
| [`docs/TESTING_GUIDE.md`](docs/TESTING_GUIDE.md) | **full test coverage** — the 7 layers, what to test when, security/safety verification |
| [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) | roles, images, sizing, observability (scraping only the api shows you nothing about scanning) |
| [`VANTARI_BUILD_SPEC.md`](VANTARI_BUILD_SPEC.md) | the full original design spec (authoritative) |
| [`context.md`](context.md) | running engineering log: what's done, what's known-broken, and why |

New to the codebase? `ARCHITECTURE.md` → `SECURITY.md` §2 (why domain control ≠
scanning authorisation) → ADR-0005 and ADR-0008. Those explain the constraints
that shape everything else.

## Status

**Phases A–G are code-complete (559 tests). Not yet validated on real
infrastructure, and the production exit gate has not been run.**

| Area | State |
|------|-------|
| Core (scope engine, fingerprints, severity, lifecycle, plans, signal) | ✅ built + exhaustively unit-tested |
| Politeness limiter — fleet-shared (Redis) + degrading, wired into every scan | ✅ (ADR-0012); every scanner subprocess rate-capped (ADR-0013) |
| Modules + pipelines (recon → probe → crawl → scan → secrets → CVE → notify) | ✅ end-to-end against fakes |
| Scheduler + worker execution (arq), cascade, cadence, fairness cap | ✅ (fairness cap unexercised at scale) |
| API — auth, tenant isolation, plan quotas; Next.js dashboard | ✅ (security suite in `tests/security/`) |
| Observability — Prometheus/Grafana, Sentry, per-process `/metrics` | ✅ (ADR-0011) |
| Encrypted Mongo backups, scope-feed auto-update, prod compose | ✅ (ADR-0014) |
| Unit + integration + security tests | ✅ 559 passing, ruff clean |

**What stands between here and release** — see `context.md` for the running log:

- **Nothing has run against real infrastructure in this repo's CI env** — Docker
  images unbuilt, Helm chart unrendered, Redis rate-limit Lua and the Mongo scope
  feed exercised only against fakes, **no backup ever restored**.
- **The §7 exit gate** — 7 days unattended with real tenants — has not been run.
- **No load test** yet (§8: 100 tenants / 10k assets / 1M findings, p99 < 500ms).
- **CVE/KEV match latency (§15)** is not measurable — `CveRecord` lacks a
  `published` timestamp.

> A recurring lesson from the engineering log: several controls passed a green test
> suite while being **dead code or broken at the seams** (the politeness limiter was
> never called; backups couldn't run). Treat "tests pass" as necessary, not
> sufficient — the real gate is exercising it on live infra.

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
