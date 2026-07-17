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
  - `ratelimit` — token bucket **and** `subprocess_rate_for` (ADR-0009).
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
  to `core/metrics.py` (ADR-0010); `/metrics` is rendered by `api/main.py`.
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
5. **Politeness** — ≤10 rps/target. In-process I/O via the token bucket;
   subprocesses get a derived `-rate` (ADR-0009), published to `/metrics`.

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
- **Latency metrics** (§15 time-to-first-finding, KEV-match latency) are not
  instrumented.
- **Phase G** is largely stubbed: `daemon/metrics.py` is a hand-rolled registry,
  Sentry is a placeholder, no verified encrypted backups, no 7-day unattended run.
- **Never run at multi-tenant scale**; the fairness cap is coded but unexercised.

Build phases: A foundation · B core pipeline · C API/auth · D attacker's edge ·
E frontend · F notifications+reports · G hardening.
