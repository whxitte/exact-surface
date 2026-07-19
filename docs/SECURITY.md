# Vantari Security Posture

Vantari is an outside-in scanner that holds sensitive data about customers'
attack surfaces, and that *points scanners at the internet on their behalf*. Two
things therefore matter as much as the findings it ships:

1. **We must never scan something we aren't authorised to scan.** That is a legal
   and AUP risk, not a bug class.
2. **One tenant must never see another's data.**

This document is the working reference for both. Every claim here names the code
that enforces it and the test that proves it — if you change one, change all
three.

---

## 1. Ethical boundary — detection only

Vantari **detects, it does not exploit** (§3.10). Operationally: no payload that
modifies target state, causes denial of service, or exfiltrates data beyond a
minimal benign proof. Nuclei runs with `-etags dos,intrusive,fuzz` excluded
(`modules/scanning/nuclei.py`). Aggressive scanners only ever run against
confirmed-dedicated infrastructure (§3 below).

---

## 2. The authorisation chain

Nothing is scanned until **all** of these hold. They are separate gates on
purpose — each one alone is insufficient.

| Gate | Proves | Enforced in |
|---|---|---|
| Domain verification (DNS-TXT / HTTP-file) | you control the apex | `core/verification.py` |
| Authorization record | you *asked* for it, with a ToS version + actor + timestamp | `db/authorizations.py`, `pipelines/orchestrate.run_program` |
| Plan quota | the tenant is entitled to scan this program | `core/plans.py`, scheduler + `run_program` |
| Scope decision | this specific host+IP may take this specific action | `core/scope.py` |

`run_program` refuses (raises `AuthorizationRequired`) without a current
authorization record — not just the API. That matters because a job can reach a
worker from a stale Redis queue, a retry, or a direct call.

### 2a. Why domain control ≠ scanning authorisation (§9b)

**This is the subtlest and most important rule in the product.**

Proving you control `acme.com` proves you control DNS. It does **not** prove you
own the IPs that `acme.com`'s subdomains resolve to. Anyone can point
`x.acme.com` at any IP address on the internet.

So a resolved IP is *classified* before any active work
(`core/scope.classify_ip`):

- `PRIVATE` / `LOOPBACK` / `LINK_LOCAL` (incl. the cloud metadata IP
  `169.254.169.254`) / `CGNAT` / `MULTICAST` / `RESERVED` → **hard deny, never
  overridable.** If *any* resolved IP of a host is in this set, the whole host is
  denied — a DNS-rebinding guard.
- `CDN` / `CLOUD_SHARED` / `PUBLIC` → **HTTP-layer probing only.** No port scan,
  no content bruteforce, no aggressive nuclei. That infrastructure belongs to
  Cloudflare/AWS/etc., not the customer.
- `DEDICATED` → **full action set.**

### 2b. How a CIDR *earns* `DEDICATED` (ADR-0008)

A customer can list CIDRs on their authorization record. Listing is a **request,
not a grant**:

- The API accepts **plain CIDR strings only** (`AuthorizationCreate.ip_scope:
  list[str]`). It records them `pending`, HTTP-layer-only. The client cannot
  express `ip_class`, `action_set`, or `confirmed_via` — those are server-decided.
- Before each scan the **worker** resolves the ASN ranges actually announced by
  the verified apex (`asnmap`) and checks each requested CIDR against them
  (`pipelines/orchestrate.confirm_authorization_ip_scope`). The verdict is written
  back onto the authorization record, so it is auditable (§5d).
- `build_program_scope` honours an entry **only** if
  `confirmed_via` starts with `asnmap:` (`core/scope.is_asn_confirmed`).
  `ip_class == "dedicated"` alone is *not* sufficient.
- A **CDN edge is never promoted**, even if the ASN matches — `evaluate()`
  computes `in_dedicated_cidr = cls != IpClass.CDN and addr in dedicated_nets`.
  Defence in depth: a bad or stale CIDR must not unlock a CDN.
- **Fails safe.** If asnmap is missing, times out, or errors, *nothing* is
  confirmed. Losing ASN data must never grant access.
- **Re-checked every run**, so a range the customer stops announcing drops back
  to HTTP-only automatically. Authorization is never trusted forever.

> **Known limitation.** Apex-ASN is a *proxy* for org ownership. A CDN-fronted
> apex announces the CDN's ASN, so such a customer's real origin block will not
> auto-confirm. That is deliberate (deny beats guess); those customers use the
> explicit `scan_shared_infra` opt-in instead.

**History:** this was a real vulnerability, not a hypothetical. `ip_scope` was
once stored verbatim from the request body, so a tenant could point a subdomain
they controlled at *any* IP, declare that block "dedicated", and unlock port
scanning of third-party infrastructure. Guard tests:
`tests/security/test_authorization_self_grant.py`,
`tests/unit/test_scope_confirmation.py`.

### 2c. `scan_shared_infra` — the explicit opt-in

A customer who genuinely owns the cloud their domain runs on can set
`scan_shared_infra` on the program. This extends the full action set to
`CLOUD_SHARED` / `PUBLIC` IPs. It **never** unlocks a third-party CDN edge, and
**never** overrides a hard-deny class.

---

## 3. Central scope enforcement (the #1 control)

`core/scope.py` is deliberately **pure** — no DNS, no sockets, no DB — so its
decisions are exhaustively testable. Every network module obtains a
`ScopeDecision` before any I/O; a call that skips it is a defect.

Exhaustively tested in `tests/unit/test_scope.py` and
`tests/unit/test_scope_confirmation.py`. **A failure there is a release blocker.**

Pipeline-level proof (that a real pipeline consults the engine, not just that the
engine works) lives in `tests/integration/test_scope_enforcement_pipeline.py`.

---

## 4. Politeness, rate limiting & provider AUP

Scanning shared cloud infra too fast draws abuse reports and gets the platform's
cloud account terminated. Two *different* mechanisms enforce the ≤10 requests/sec
per-target ceiling (`settings.global_rate_per_target`), because they cover
different kinds of I/O:

**In-process I/O** (`core/ratelimit.py`) — a token bucket, backed by Redis in
production so the ceiling holds across the whole worker fleet, not per process.
This governs the requests Vantari itself makes at customer hosts: the takeover
body-fetch and the secret fetcher. Pipelines pace them with
`throttled_fetch(fetch, limiter)` wrapped around their injected fetch function, so
the ceiling applies by construction rather than by each module remembering to ask.
Scan traffic uses `acquire()` (wait) rather than `allow()` (drop) — politeness must
cost time, not coverage.

> This was a live bug, and a total one: **the limiter was never called at all.**
> `RedisBucketStore` was never constructed, `allow()` had no callers, and
> `RunContext` — the object meant to carry the limiter to modules — is never
> instantiated. So takeover and secret fetches went out unthrottled, and even if
> they had not, `build_limiter` defaulted to an in-memory store, which with 2–3
> worker replicas means 2–3× the per-target cap. Every unit test passed the whole
> time: they tested the bucket math, which was correct. Nothing tested that the
> control was reachable. See ADR-0012.

**When Redis is down** the limiter degrades to a local bucket at
`rate ÷ worker_fleet_size` rather than failing open (which would silently remove
the ceiling) or failing closed (which would stop all scanning). The divisor means
that even if every worker degrades at once, the aggregate stays within the cap —
so `VANTARI_WORKER_FLEET_SIZE` **must be ≥ your real replica count**. In prod, a
worker that cannot reach a shared store refuses to start.

**Scanner subprocesses** (`core.ratelimit.derive_subprocess_rate`) — a token bucket
**cannot** govern a subprocess: naabu, httpx, katana, nuclei, feroxbuster and ffuf
each send their own traffic, so our limiter never sees it. The ceiling is handed to
the tool up front, via its rate flag (`-rate`/`-rl`/`--rate-limit`), derived from
the per-target cap. For a tool given many hosts at once the flag is an aggregate
(`cap × hosts`, clamped by an absolute ceiling); for a per-host invocation it is the
cap itself. Every derivation publishes `vantari_subprocess_per_target_pps{tool}`, so
the ceiling is verifiable per tool rather than asserted. See ADR-0009 (naabu) and
ADR-0013 (the rest).

> This was a live bug, twice over. First: `port_scan.py` called naabu without a
> rate, using naabu's flat `1000` default — **100× the cap** — while naabu's
> docstring wrongly claimed the limiter covered it (ADR-0009). Then an audit found
> the *other five* tools passed no rate flag at all: httpx/katana/nuclei ran at
> their 150 rps default (15× the cap) and feroxbuster/ffuf were unlimited. `-c` and
> `-t` look like rate controls but bound concurrency, not rate (ADR-0013).

**Verifiable, not asserted.** `/metrics` exposes
`vantari_politeness_rate_limit_pps` (the cap) and, per tool,
`vantari_subprocess_rate_pps{tool}` (aggregate) and
`vantari_subprocess_per_target_pps{tool}` (derived). The §15 exit gate is
"no subprocess exceeds the cap *verified by metrics*" — these are that evidence, and
`SubprocessRateExceedsPolitenessCap` pages if any tool crosses it. Tests:
`tests/unit/test_politeness_rate.py`, `tests/unit/test_subprocess_rate.py`.

Masscan is disabled in v1 (ADR-0004) and stays disabled until Vantari has
dedicated, abuse-contact-registered netblocks.

---

## 5. Tenant isolation

Multi-tenant from line one. Every document carries `tenant_id`; every query
filters by it; every compound index leads with it.

The choke point is `api/deps.require_program`: it scopes the lookup to the
caller's tenant and returns **404** — never 403, which would confirm the resource
exists. A valid token for tenant A gets 404 for every one of tenant B's
resources.

Proven by `tests/security/test_tenant_isolation.py`, which parametrises **every**
program-scoped GET route plus the mutating routes, the API-key path, sub-resource
IDs (notification channels), and the websocket stream.

---

## 6. Authentication & authorisation

- **Passwords**: bcrypt (72-byte input cap handled explicitly).
- **Sessions**: HS256 JWT. `decode_token` pins `algorithms=[HS256]`, which
  rejects the `alg:none` downgrade. Expiry is verified.
- **API keys**: `vnt_` prefix, shown exactly once, stored **only** as a SHA-256
  hash.
- **Email verification**: signup mints a one-time token (24h expiry) and emails a
  link; `POST /auth/verify-email` consumes it (replay → 400). Resend is authed
  with a per-user 60s cool-off so it can't be used to bomb an inbox. Gating
  program creation on it is a deployment setting
  (`require_email_verification` — off in dev, on in prod).
- **RBAC**: `require_owner` (OWNER|ADMIN) guards privileged operations — minting
  API keys, deleting a program, creating the authorization record, managing
  integration secrets. An admin cannot mint an owner-scoped key (no privilege
  escalation via `body.role`).
- **Rate limiting**: per **tenant** (from the JWT), falling back to IP for
  pre-auth endpoints (`api/rate_limit.py`).

**Structural guard:** `tests/security/test_route_auth_coverage.py` enumerates
*every* HTTP route on the app and asserts that calling it without credentials
never returns 2xx. Public routes are an explicit allow-list — adding a new data
route without auth fails the suite rather than shipping an open endpoint.

Adversarial coverage (`tests/security/test_jwt_hardening.py`): missing token,
malformed token, `alg:none` forgery, tampered signature, tampered payload,
expired token, wrong-secret token, invalid API key.

NoSQL/operator injection: path and query params are typed `str` and are only ever
equality operands *alongside* the authenticated `tenant_id` (which comes from the
verified token, never from client input). `tests/security/test_nosql_injection.py`.

---

## 7. Exposed-secret handling (§9c / ADR-0006)

Vantari must never become a plaintext honeypot of *other companies'* live
credentials. When it finds a leaked secret it **never stores the plaintext**:

- a masked hint (`AKIA••••••••7Q`),
- a keyed HMAC hash (dedup only; not reversible from the DB alone),
- a locator (URL/file/line).

Notifications and reports carry the masked value only — `alert_from_secret`
reads `doc["masked"]` and nothing else, so it cannot leak even if a doc wrongly
carried a plaintext field. Raw evidence retention ≤30 days, then purged to
masked+hash.

Tests: `tests/security/test_secret_notification_leak.py`, `test_secrets.py`,
`test_notify.py`, `test_reports.py`.

---

## 8. Signal quality as a safety property

A scanner nobody trusts gets ignored, and an ignored scanner is a security
liability. §15 makes the **user-marked false-positive rate** the make-or-break
metric (target <5%).

- `core/signal.py` splits **actionable** (open + medium↑) from **informational**
  inventory, and computes `false_positive_rate = FALSE_POSITIVE ÷ user-decided`.
  It returns `None` until the first triage, so a new tenant never reads as a
  fake 0%.
- CVE matching carries an explicit **confidence** (`modules/intelligence/cve_match.py`):
  only high-confidence matches alert; **any CISA-KEV match escalates to high**
  regardless; low/medium accumulate silently in the UI.

---

## 9. Application security

- **Server-side input validation on the trust boundary.** Frontend checks are advisory
  — a request from curl/Burp ignores them — so every externally-supplied value is
  validated in the API before it is persisted or acted on (`core/validation.py`, wired
  into the Pydantic schemas in `api/schemas.py`). A bad value is a clean 422, never a
  persisted/acted-on value. Covered: apex domain (must be a bare registrable domain, not
  a URL/IP/path — it feeds scope + scanning), exclusion hosts/CIDRs (format + count
  caps), authorization CIDRs, and notification channel config (below). Numeric overrides
  (cadence/timeout/alert-policy) are clamped and unknown keys dropped; the report
  `format` is whitelisted; module toggles are filtered to the known set.
- **NoSQL/operator injection is inert.** Path/query params are typed `str` and used only
  as equality operands *alongside* the token-derived `tenant_id`, so a `{"$ne": null}`
  is treated as a literal that matches nothing (`tests/security/test_nosql_injection.py`).
  Models use `extra="ignore"`, so mass-assignment of unexpected fields is impossible.
- **Outbound-webhook SSRF is closed.** A notification channel URL is user-supplied and
  the server POSTs to it on every alert. Delivery goes through the SSRF-safe guarded
  session (`modules/safe_http.guarded_post`): the filtering resolver blocks any host
  that resolves to a non-public address (metadata/RFC1918/loopback — incl. DNS
  rebinding) and redirects are off. Input-time validation additionally rejects non-http
  schemes and forbidden IP literals, and constrains a Telegram bot token so it can't
  rewrite the request host. This complements the in-process fetch guard (§3.10) used by
  the takeover/secret/403-bypass modules.
- **Request bodies are size-capped** (512 KiB) by middleware before buffering, so an
  oversized JSON payload is a 413, not a memory-DoS.
- Prod refuses to boot with insecure default secrets (`Settings.assert_prod_safe`).
- CORS locked to the frontend origin in prod; frontend ships no inline scripts.
- Trivy scans in CI (`.github/workflows/ci.yml`).
- Sentry ships **no PII** (`send_default_pii=False`).
- Audit trail (`db/audit.py`) records scan runs; retention: findings 2y, raw scan
  output 90d, raw secret evidence 30d.

---

## 10. Reporting a vulnerability

Email security@vantari.io with details and a reproduction. We trade in findings;
we take ours seriously.
