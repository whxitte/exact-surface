# Vantari

**Continuous external attack-surface intelligence — detection only.**

Vantari continuously answers one question for every domain a customer owns:
*"What does an external attacker see right now, and what can they do with it?"*
It runs the tooling real attackers use (subfinder, httpx, nuclei, katana, naabu,
wordlist fuzzing), is state-aware (one alert per genuinely new fact, not per
re-scan), multi-tenant from line one, and **never exploits — only detects**.

> Full design: [`VANTARI_BUILD_SPEC.md`](VANTARI_BUILD_SPEC.md). Decisions:
> [`docs/ADRs/`](docs/ADRs/).

## Status

**Phase A (Foundation) — complete and verified.**

| Piece | State |
|-------|-------|
| Central scope engine (`core/scope.py`) | ✅ built + exhaustively tested |
| Content-hash fingerprints (`core/hashing.py`) | ✅ |
| Politeness rate limiter (`core/ratelimit.py`) | ✅ token bucket, Redis + in-memory |
| Config / logging / models / severity / lifecycle | ✅ |
| Mongo layer + index bootstrap (`db/mongo.py`) | ✅ |
| Task-queue skeleton (`taskqueue/`) | ✅ interfaces (execution: Phase B) |
| Daemon health + `--dry-run`, API `/healthz` | ✅ |
| Docker images + compose stack | ✅ |
| Unit tests | ✅ 70 passing |

Next: **Phase B** — implement modules 1–10 (recon → probe → scan → crawl) and wire
the scheduler/worker execution path.

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
