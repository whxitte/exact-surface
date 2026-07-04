# Vantari Architecture

Continuous external attack-surface intelligence — **detection only**. Outside-in,
agentless, multi-tenant, state-aware.

## The loop
```
scheduler (state-aware, per-cadence)
   → enqueue jobs (Redis / arq, per-tenant fair)
       → worker pulls job
           → authorization gate + scope decision (core/scope.py)
               → pipeline runs a module within its permitted action set
                   → idempotent upsert by content-hash (is_new fires once)
                       → correlate → notify channels → export reports
```

## Layers
- **core/** — pure logic, no I/O: `scope` (the safety control), `hashing`
  (idempotency keys), `ratelimit` (politeness), `severity`, `lifecycle`,
  `secrets_policy` (masking), `cpe`, `fingerprint`, `config`, `models`.
- **db/** — one repo per collection, all tenant-scoped; `base.Repository` does the
  `$setOnInsert`/`$set` idempotent upsert.
- **modules/** — tool wrappers (recon/probing/scanning/crawling/ports/
  content_discovery/dorking/osint/intelligence/notification/reporting), each with
  an injectable runner so it's testable offline.
- **pipelines/** — orchestrators that compose modules, enforce scope per target,
  and persist results.
- **taskqueue/** — cadence policy, the state-aware scheduler, dispatch, arq client.
- **daemon/** — health, metrics, and the scheduler supervisor (`--dry-run` gate).
- **api/** — FastAPI: auth (JWT + API keys), tenant-scoped routes, ws stream,
  per-tenant rate limiting.
- **frontend/** — Next.js 14 dashboard.

## Non-negotiable principles
State-awareness · idempotency · multi-tenancy from line one · async everywhere ·
central scope enforcement · detection-only. See `docs/SECURITY.md` and the ADRs
in `docs/ADRs/` (MongoDB choice, PD toolchain, task queue, masscan-disabled,
scope engine, secret handling, taskqueue naming).

## Data model
Every model extends `TenantScopedModel` (carries `tenant_id`). Observed entities
extend `StatefulModel` (adds `program_id`, `fingerprint`, `first_seen`/`last_seen`,
`is_new`). The content-hash `fingerprint` is the unique upsert key per
`(tenant_id, fingerprint)`.

Build phases: A foundation · B core pipeline · C API/auth · D attacker's edge ·
scheduler cadence · E frontend · F notifications+reports · G hardening.
