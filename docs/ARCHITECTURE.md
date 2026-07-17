# Vantari Architecture

Continuous external attack-surface intelligence — **detection only**. Outside-in,
agentless, multi-tenant, state-aware.

Start here, then read `docs/SECURITY.md` (the control model — the part that will
bite you if you get it wrong) and `docs/API.md`. Design decisions live in
`docs/ADRs/`.

---

## The loop

```
scheduler (state-aware, per-cadence, per-tenant fair)
   → enqueue jobs (Redis / arq)
       → worker pulls job
           → authorization gate  (a current authorization record, or refuse)
           → plan-quota gate     (§13 — checked at enqueue AND here)
           → ip-scope confirmation (asnmap → what is really "dedicated")
           → scope decision      (core/scope.py — per host, per action)
               → pipeline runs modules within the permitted action set
                   → idempotent upsert by content-hash (is_new fires once)
                       → correlate → notify (alert policy) → reports
```

Every gate is re-checked on the worker, not only at the API. A job can arrive
from a stale Redis queue, a retry, or a direct call — the API is UX, the worker
is the boundary.

## Runtime roles

| Role | Image | Notes |
|---|---|---|
| **api** | slim python | no scan toolchain — §3.8 keeps it separate. Consequence: anything needing a tool (e.g. `asnmap`) must run on the worker. |
| **worker** | `pipeline` (all recon tools) | stateless; scale horizontally |
| **scheduler** | slim | singleton enqueuer |
| **mongo / redis** | — | Redis backs both the queue and the rate-limit buckets |

---

## Layers

- **core/** — pure logic, no I/O. Unit-testable with zero mocks.
  - `scope` — **the safety control** (§9b). Classify IP → decide actions.
  - `plans` — §13 tier limits. Fails closed to FREE.
  - `signal` — actionable-vs-informational + the §15 false-positive rate.
  - `ratelimit` — token bucket, fleet-shared+degrading store (ADR-0012), **and**
    `derive_subprocess_rate` for every scanner subprocess (ADR-0009 + ADR-0013).
  - `metrics` — the Prometheus registry (counters/gauges/histograms). In `core`, not
    `daemon`, so the limiter can instrument itself — ADR-0010.
  - `hashing` (idempotency keys) · `severity` · `lifecycle` (finding state
    machine) · `alert_policy` · `secrets_policy` (masking) · `liveness`
    (live-vs-gone) · `cpe` · `fingerprint` · `email` · `config` · `models`.
- **db/** — one repo per collection, all tenant-scoped; `base.Repository` does the
  `$setOnInsert`/`$set` idempotent upsert.
- **modules/** — tool wrappers, each with an **injectable runner** so it is
  testable offline (no binaries in CI).
- **pipelines/** — orchestrators that compose modules, enforce scope per target,
  and persist.
- **taskqueue/** — cadence policy, the state-aware scheduler, dispatch, arq client.
- **daemon/** — health checks + the scheduler supervisor (`--dry-run`). Metrics moved
  to `core/metrics.py` (ADR-0010); `metrics_server.py` exposes a headless process's
  registry over HTTP (ADR-0011).
- **api/** — FastAPI: auth, tenant-scoped routes, ws stream, per-tenant limits.
- **frontend/** — Next.js 14 dashboard.

**Dependency direction:** `api`/`pipelines`/`taskqueue` → `db` → `core`. `core`
depends on nothing internal — which is why the metrics registry had to move into
it before the rate limiter could be instrumented (ADR-0010).

---

## The five control points

If you're changing scan behaviour, one of these is probably the thing you need to
respect. All are re-enforced worker-side.

1. **Authorization record** — no record, no scan (`AuthorizationRequired`).
2. **Plan quota** — Free 1 / Pro 5 / Business 25 / Enterprise ∞. Over-quota
   programs are never enqueued and `run_program` refuses them. Unknown plan →
   FREE, never unlimited.
3. **IP-scope confirmation** — a customer-listed CIDR is a *request*. Only
   `asnmap`-confirmed ranges become `dedicated`. ADR-0008.
4. **Scope decision** — hard-deny classes (RFC1918/metadata/…) are never
   overridable; CDN/cloud-shared get HTTP-layer only; full actions require
   confirmed-dedicated.
5. **Politeness** — ≤10 rps/target. In-process requests at customer hosts are paced
   by the token bucket, shared across the fleet via Redis and degrading to a
   divided local share if Redis dies (ADR-0012). Every scanner subprocess
   (naabu/httpx/katana/nuclei/feroxbuster/ffuf) gets a rate flag derived from the
   same cap (ADR-0009 + ADR-0013), since the bucket cannot see a subprocess's
   sockets. Both published to `/metrics` and covered by one alert. Not covered:
   tools that talk to third-party APIs/resolvers rather than customer hosts
   (subfinder, dnsx, gau, asnmap).

---

## Data model

Every model extends `TenantScopedModel` (`tenant_id`). Observed entities extend
`StatefulModel` (`program_id`, `fingerprint`, `first_seen`/`last_seen`, `is_new`).
The content-hash `fingerprint` is the unique upsert key per
`(tenant_id, fingerprint)` — see `core/hashing.py` for exactly what goes into each
(volatile fields are excluded on purpose; a changed response body is the same
finding).

**Findings** additionally carry a lifecycle state (`core/lifecycle.py`):
`NEW → TRIAGED → CONFIRMED → RESOLVED`, plus `FALSE_POSITIVE` / `ACCEPTED_RISK`,
and `REGRESSED` when a resolved finding reappears (alerts once).

### State-awareness: `is_new` and "gone"

- `is_new` fires **exactly once** per genuine insert, and is cleared only when a
  notification is actually delivered — so an alert fires once per real
  appearance, not once per scan.
- **Live vs gone** (`core/liveness.py`): nothing is deleted. An item is marked
  `gone` only when a *full-coverage re-run of the module that produced it*
  stopped reporting it. A partial/failed scan therefore can't mass-mark
  everything gone.

---

## Configuration resolution

Cadence, timeouts, and alert policy all resolve the same way:

```
built-in defaults  ←  tenant defaults  ←  program overrides     (most specific wins)
```

Values are clamped server-side (sub-floor cadence raised, absurd timeouts capped),
so persisted config can never break a stage.

---

## Alerting

`pipelines/notify.py` delivers only `is_new` items, gated by the program's
**alert policy**: a severity floor (default `medium`), per-family toggles
(findings/secrets/leaks/CVEs), a CVSS floor for CVEs, and opt-in change events
(new subdomain / new open port) that fire **only after the baseline scan** — so
the first enumeration doesn't page for every subdomain.

Secrets/leaks are formatted from **masked** fields only; a plaintext secret
cannot reach a channel (§9c).

Signal quality is a first-class metric, not a nicety: `/stats` reports
`open_actionable` vs `informational` and the §15 `false_positive_rate`. A scan
emitting 700 info-level detections and 3 real issues should read as "3".

---

## Observability

**The registry is per-process.** `core/metrics.py` is plain in-memory state, so
there is no shared store — each process holds only the samples it emitted itself.
This has one consequence that catches everyone: *the metrics that describe
scanning are not emitted by the API*. Stage outcomes, run durations, politeness
decisions and port-scan rates all happen in the **worker**; scheduler liveness
happens in the **scheduler**. Neither runs an HTTP server of its own, so
`daemon/metrics_server.py` gives them one (ADR-0011) and Prometheus scrapes all
three roles separately (`docker/prometheus.yml`). Scraping only the API shows you
HTTP counters and nothing about scanning.

What is emitted, and why each earns its place:

| Metric | Role | Answers |
| --- | --- | --- |
| `vantari_scheduler_last_success_timestamp` | scheduler | Is scanning still happening? |
| `vantari_scheduler_ticks_total{status}` · `..._jobs_enqueued_total` | scheduler | Ticking but enqueueing nothing? |
| `vantari_scan_stage_total{stage,status}` · `..._duration_seconds` | worker | Which stage is failing, timing out, or slowing? |
| `vantari_scan_run_total{pipeline,status}` · `..._duration_seconds` | worker | Are whole runs completing? |
| `vantari_subprocess_per_target_pps{tool}` · `..._rate_pps{tool}` | worker | §15: does each scanner subprocess stay under the cap? |
| `vantari_politeness_decisions_total{decision}` · `..._rate_limit_pps` | worker | Is the limiter throttling? |
| `vantari_alert_latency_seconds` | worker | §15 notify-hop latency. |
| `vantari_http_requests_total{method,status}` | api | API traffic/errors. |

**No metric carries a tenant, program, or host label** — deliberately. It bounds
cardinality (a per-target label grows without limit in hosts ever scanned) and it
keeps the listener free of tenant data, which is what lets it bind the container
network without being an exposure.

`vantari_scheduler_last_success_timestamp` deserves specific mention: `run_forever`
swallows tick exceptions so one bad tick cannot kill the loop, which means a
scheduler failing *every* tick still has a live process and an answering port
while never enqueueing again. A liveness probe cannot see that; the gauge can.

Dashboards (`docker/grafana/dashboards/`) and alerts (`docker/alerts.yml`) are
provisioned from git, not click-ops. `tests/unit/test_dashboard_queries.py` asserts
every panel/rule references a metric something actually emits — a renamed metric
otherwise leaves a permanently empty panel that looks like "no problems".

Sentry (`core/observability.py`) is DSN-optional and initialised by **all three**
entrypoints. `send_default_pii=False`.

---

## Testing shape

| Suite | Proves |
|---|---|
| `tests/unit/` | pure logic — scope deny-list, hashing, plans, signal, lifecycle, rate derivation |
| `tests/integration/` | pipelines actually consult the controls (scope enforcement, authorization gate, plan quota at enqueue, ip-scope confirmation) |
| `tests/security/` | the adversarial view — JWT forgery, cross-tenant IDOR, route-auth coverage, NoSQL injection, secret-leak-in-notification, authorization self-grant |
| `tests/e2e/` | the self-serve workflow through the real app |

Everything runs offline: no binaries, no DB, no network. `FakeMongo` implements
just enough of motor; every tool wrapper takes an injectable runner.

---

## Known gaps (keep honest)

- **CVE/KEV match latency is not measured** (§15 target <60 min). `CveRecord` has
  no `published` field, so the NVD parser must carry it first. Alert latency
  (detection→delivered) *is* measured: `vantari_alert_latency_seconds`.
- **`nuclei_watch` has no default template lister.** The pipeline is wired and
  tested, but nuclei's `-tl` output contract has not been verified against the
  pinned binary, so the lister must be injected. Without one the stage reports
  `skipped` honestly rather than silently finding nothing. Verify against a real
  nuclei build, then add the default.
- **`cloud_buckets` implements only the permutation half of §6 module 18.** The
  `cloudlist` half (enumerating a customer's cloud assets via provider APIs) is
  not built — it needs the customer's cloud credentials, a trust escalation we
  have not taken.
- **Search-engine response shapes are from vendor docs, not a live key.** Brave
  and SerpAPI wrappers are unit-tested against fixtures; verify against a real key
  before relying on them.
- **CVE/KEV match latency (§15, target <60min) is still not measurable.**
  `CveRecord` has no `published` field, so there is no origin timestamp to measure
  from; `parse_nvd` must carry it before the metric can mean anything. Alert
  latency (finding first-seen → notified) *is* instrumented
  (`vantari_alert_latency_seconds`), but that is only the notify hop — it is not
  the signup→first-alert figure §15 asks for.
- **Phase G is nearly done.** Observability, rate-limit degradation (ADR-0012),
  encrypted backups, per-tool subprocess caps (ADR-0013) and scope-feed auto-update
  (ADR-0014) are wired; still outstanding: a real prod compose file, and the 7-day
  unattended run itself — the exit gate, which can only be run, not coded.
- **Scope-feed updates reach workers only on restart.** The feed is distributed via
  Mongo now (ADR-0014) and the scheduler refreshes it daily, but a running worker
  builds its engine once at startup — so a refresh lands on the next rolling restart,
  not mid-process. Deliberate (ranges change monthly; no hot-reload of a safety
  control), but it is a staleness window to know about.
- **No backup has ever been restored.** The dump/encrypt/restore paths shell out to
  `mongodump`/`age`/`mongorestore`; only the pure command builders and the retention
  policy are tested. An untested backup is a hypothesis — restore one into a scratch
  database before relying on it.
- **The alert thresholds in `docker/alerts.yml` are duplicated from app config**
  because Prometheus cannot read `Settings`. `test_dashboard_queries.py` pins the
  politeness cap against `global_rate_per_target`; the others are unguarded.
- **`worker_fleet_size` is duplicated config.** It must be ≥ the real worker replica
  count or the degraded-mode guarantee is void; nothing enforces that.
- **The Redis rate-limit Lua is untested against a real Redis** — including
  `redis.call('TIME')`. Verify against live redis 7 before the unattended run.
- **`modules.base.RunContext` is dead code.** Nothing constructs it. It is the
  design that let the limiter rot (see ADR-0012); either wire it or delete it.
- **Never run at multi-tenant scale**; the fairness cap is coded but unexercised.

Build phases: A foundation · B core pipeline · C API/auth · D attacker's edge ·
E frontend · F notifications+reports · G hardening.
