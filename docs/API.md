# ExactSurface API

FastAPI. Interactive reference (always authoritative, generated from the code):
**`/docs`** · OpenAPI JSON: **`/openapi.json`**.

This file is the hand-written orientation: what the endpoints are *for*, and the
rules that aren't visible in a schema.

---

## Authentication

Two credential types resolve to the same `Principal` (`api/deps.get_principal`):

| Method | Header | Notes |
|---|---|---|
| JWT | `Authorization: Bearer <token>` | from `/auth/signup` or `/auth/login`; HS256, expiring |
| API key | `X-API-Key: exs_...` | shown once at creation, stored as SHA-256 only; scoped (see below); cannot perform human-only actions |

**Every route requires auth** except the explicit public set: `/healthz`,
`/readyz`, `/metrics`, `/auth/signup`, `/auth/login`, `/auth/verify-email`, and
the docs endpoints. This is enforced structurally by
`tests/security/test_route_auth_coverage.py`.

### Status codes you should expect

| Code | Meaning here |
|---|---|
| `401` | missing/invalid credentials |
| `403` | authenticated but not permitted (role, or unverified email) |
| `404` | not found **or not yours** — cross-tenant access is 404, never 403 |
| `402` | plan limit hit (add a domain / scan an over-quota domain) |
| `409` | precondition unmet (unverified domain, no authorization, scan already running) |
| `429` | rate limited (per tenant), or resend cool-off |

> **404 is deliberate.** A 403 would confirm the resource exists. Tenant A asking
> for tenant B's `program_id` gets 404.

---

## Auth

| Method | Path | Notes |
|---|---|---|
| `POST` | `/auth/signup` | creates tenant + OWNER user; sends verification email |
| `POST` | `/auth/login` | → JWT |
| `POST` | `/auth/verify-email` | **public** — the emailed one-time token *is* the credential |
| `POST` | `/auth/resend-verification` | authed; per-user 60s cool-off → `429` |
| `GET` | `/auth/me` | principal + `email`, `email_verified` |
| `POST` | `/auth/api-keys` | settings.manage, **human-only**; body `{name, scopes[]}`; raw key returned exactly once with the scopes actually granted |
| `GET` | `/auth/api-keys` | list keys (never the hash); revoked ones included |
| `DELETE` | `/auth/api-keys/{key_id}` | revoke, effective immediately; **human-only** |
| `GET` | `/auth/api-keys/scopes` | the scope catalogue and which of them the caller may grant |
| `GET` | `/audit` | settings.manage; every mutating call, succeeded or refused — `?limit=&before=&program_id=&actor=` |

An admin cannot mint an OWNER-scoped key (no privilege escalation).

---

## Programs (domains)

| Method | Path | Notes |
|---|---|---|
| `GET` | `/programs` | tenant-scoped list |
| `POST` | `/programs` | `402` if over plan quota; `403` if email unverified (when enforced) |
| `GET` | `/programs/{id}` | |
| `DELETE` | `/programs/{id}` | **OWNER/ADMIN**; purges all program data |
| `POST` | `/programs/{id}/monitoring?enabled=` | pause/resume without losing history |
| `POST` | `/programs/{id}/assets/{fingerprint}/monitoring?enabled=` | mute one asset |

### Verification & authorization

| Method | Path | Notes |
|---|---|---|
| `POST` | `/programs/{id}/verify/request?method=dns_txt\|http_file` | returns the token to publish |
| `POST` | `/programs/{id}/verify/check` | flips `verified` |
| `POST` | `/programs/{id}/authorization` | **OWNER/ADMIN**; requires `verified` |
| `GET` | `/programs/{id}/authorization` | shows the server's confirmation verdict |

`POST /authorization` body:

```json
{ "ip_scope": ["45.55.0.0/16"], "tos_version": "v1" }
```

`ip_scope` is a list of **plain CIDR strings** — a *request*, not a grant. The
server records them `pending` / HTTP-layer-only. They are promoted to `dedicated`
only by the worker, after `asnmap` confirms the range against the verified apex's
announced ASN, and the verdict is written back here. Sending the old object form
(`{cidr, ip_class, action_set, confirmed_via}`) is a **422** — the client cannot
assert its own class. See `docs/SECURITY.md` §2b and ADR-0008.

### Scanning

| Method | Path | Notes |
|---|---|---|
| `POST` | `/programs/{id}/scan` | `202`; `409` unverified/unauthorized/already-running; `402` over quota |
| `GET` | `/programs/{id}/scan-runs` | run history |
| `GET` | `/programs/{id}/scan-runs/{scan_id}/logs` | live tool output; `404` if the run isn't this program's |

### Configuration

| Method | Path |
|---|---|
| `GET`/`POST` | `/programs/{id}/schedule` — per-phase cadence |
| `GET`/`POST` | `/programs/{id}/timeouts` — per-stage budgets |
| `GET`/`POST` | `/programs/{id}/alert-policy` |
| `POST` | `/programs/{id}/scan-config`, `/programs/{id}/modules` |

Resolution order everywhere: **built-in defaults ← tenant defaults ← program
overrides** (most specific wins). Values are clamped server-side (a sub-floor
cadence is raised to `MIN_INTERVAL_SECONDS`; an absurd timeout is capped).

### Data reads (all tenant+program scoped)

`GET /programs/{id}/` + `assets` · `endpoints` · `findings` · `secrets` · `ports`
· `leaks` · `cves` · `deltas` · `correlation` · `attack-surface` · `reports`

`findings` accepts `?severity=`, `?state=`, `?is_new=`. Reads annotate `gone`
(see ARCHITECTURE "Live vs gone").

---

## Account-level

| Method | Path | Notes |
|---|---|---|
| `GET` | `/stats` | totals **plus** signal quality: `open_actionable`, `informational`, `findings_by_state`, `false_positive_rate` |
| `GET` | `/activity` | recent scan runs |
| `GET`/`POST` | `/schedule/defaults`, `/schedule/timeout-defaults`, `/schedule/alert-policy` | tenant-wide defaults |
| `GET`/`POST`/`DELETE` | `/notifications`, `/notifications/{channel_id}` | channels |
| `GET`/`PUT`/`DELETE` | `/integrations`, `/integrations/{name}` | **OWNER/ADMIN**; secrets are write-only, read back masked |

`false_positive_rate` is `null` until the tenant has decided at least one finding
— an empty account is not 0%.

---

## Websockets

| Path | Notes |
|---|---|
| `/ws/findings?token=<jwt>` | snapshot of currently-new findings |
| `/ws/activity?token=<jwt>` | scan-run snapshot + live updates via Redis pub/sub |

Auth is the `token` query param (browsers can't set headers on a WS handshake).
Invalid → close `4401`. Both scope every query to the token's `tenant_id`.

---

## Ops

| Path | Notes |
|---|---|
| `/healthz` | liveness — always 200 if the process is up; never touches the DB |
| `/readyz` | readiness — real dependency checks; `503` if a critical one fails |
| `/metrics` | Prometheus text exposition |

Keeping `/healthz` DB-free is deliberate: a Mongo blip must not cause a restart
loop.

## API-key scopes and human-only actions

A key acts with its creator's live permissions, narrowed by its scopes. Ask for more
than the creator holds and the response lists what was actually granted.

| Scope | Allows | Needs from the creator |
|---|---|---|
| `read` | every read route — implicit on all keys | `view` |
| `scans:run` | `POST …/scan`, `…/scan-runs/{id}/cancel`, `…/bypass-403` | `programs.manage` |
| `programs:write` | `POST /programs`, modules, monitoring, schedule, timeouts, alert policy | `programs.manage` |
| `playground:run` | `POST /playground/run`, save/delete workflows | `programs.manage` |
| `settings:write` | writes under `/notifications`, `/integrations`, `/schedule` | `settings.manage` |

**No scope permits these** — they return `403 "this action requires an interactive
session"` for any key: `…/verify/request`, `…/verify/check`, `…/authorization`,
`…/scan-config`, `DELETE /programs/{id}`, everything under `/members`, and creating
or revoking API keys. Do them as a person; the audit log records who.

A missing scope is `403 "this API key does not have the 'x' scope"`. A revoked or
unknown key is `401 "invalid api key"` — the same message for both, deliberately.
