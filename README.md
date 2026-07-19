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
Stop there — don't try to verify in the UI. (Email verification is off in dev by default, so signup + add-program won't be blocked. If your .env set VANTARI_REQUIRE_EMAIL_VERIFICATION=true, the verification link is printed in the API logs: docker compose -f docker/docker-compose.yml logs api | grep verify.)

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
⚠️ One honest caveat: only ever do this bypass for a domain you actually own, on your own instance. Domain verification is the control that keeps Vantari from scanning someone else's property — bypassing it for a domain you don't control is exactly the AUP/legal violation the whole authorization chain exists to prevent. quipohealth.com is yours, so you're clear.

It's posible to set  a quick mongosh one-liner to flip scan_shared_infra on (so this run includes port + content-discovery against our own infra)

---

Email — why/what/where? It's for signup email verification only (the confirm-your-address link), and it's config, not a UI setting — that's why you don't see it in the app. In dev, VANTARI_EMAIL_TRANSPORT=log just prints the link to the API logs (no provider needed). To send real mail, set smtp + any provider's SMTP creds in .env. "Provider-agnostic" means it speaks plain SMTP, so Resend/Brevo/SES all work. Nothing to configure to test scanning.

Tech-aware nuclei — will it lose generic findings (expired TLS, etc.)? No. The safe baseline is still exposure, misconfig, tech, ssl, cve, default-login — TLS/expiry, generic misconfigs, CVEs all still run. The tech tags are added on top (a WordPress host also gets WordPress templates). It's strictly more coverage, never less, on the safe scan. Only the aggressive run (confirmed-dedicated infra) uses the full library.

Where's the ASN mapper in the pipeline? It's not a visible stage — it runs inside authorization confirmation (confirm_authorization_ip_scope, before scanning), which is why it's not in the stepper. It's the mechanism that answers your next question:

How is the "point x.mydomain.com at any IP, declare /24 dedicated, scan third-party infra" risk prevented? The client only ever requests CIDRs — they're recorded as unconfirmed (HTTP-layer only). Before each scan, the worker runs asnmap on your verified apex's real announced ASN and promotes a CIDR to dedicated only if it actually falls in that ASN's ranges. Self-attestation never unlocks aggressive scanning. That's exactly why you saw "no confirmed-dedicated hosts — ports/content withheld (§9b)" — quipohealth.com is on shared/cloud infra, so port scan + content discovery + active nuclei were correctly withheld. To scan your own cloud infra, flip the "Scan my cloud infra" toggle (scan_shared_infra) — only because you own it.

What is nuclei_watch? It baselines which nuclei templates currently match your stack, then alerts when a NEW template starts matching (e.g. a fresh CVE template now fires on your host). It's opt-in because its template-lister contract is unverified against the pinned binary.

Grafana — creds/config? http://localhost:3001, login admin / admin in dev (set GRAFANA_ADMIN_PASSWORD to change). Nothing to configure — the Prometheus datasource and the "Vantari — Operations" dashboard are auto-provisioned. Panels populate during a scan (worker/scheduler are scraped on :9100).

