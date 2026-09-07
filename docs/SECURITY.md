# ExactSurface Security Posture

ExactSurface is an outside-in scanner that holds sensitive data about operators'
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

ExactSurface **detects, it does not exploit** (§3.10). Operationally: no payload that
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

### 2b. Who these gates actually protect against (read this before you quote them)

The chain above is enforced against **every user of the product**. It is *not*
enforced against **the operator of the deployment**, and on self-hosted software it
cannot be.

Verification state lives in MongoDB. The operator runs that database. Somebody with
shell access can write a verified program and an authorization record by hand:

```js
db.programs.insertOne({tenant_id:"t1", program_id:"p9",
                       apex_domain:"someone-elses.com", verified:true, enabled:true})
db.authorizations.insertOne({tenant_id:"t1", program_id:"p9", apex_verified:true})
```

…and the scanner will treat that domain as authorised. **There is no cryptographic
step that could prevent this without the project becoming a gatekeeper of what every
operator is allowed to scan** — which would mean phoning home with the operator's
domain list, and would break air-gapped deployment outright. We have chosen not to do
that, and the trade is stated here rather than hidden.

So be precise about what each control buys:

| Threat | Protected? |
|---|---|
| A user of the product scans a domain they do not control | **Yes** — verification is required and cannot be skipped in the UI or API |
| A member with an API key targets a third party | **Yes** — same gates, no path around them |
| A bug or bad input causes an out-of-scope request | **Yes** — the scope engine is a separate, central check (§3) |
| A pipeline stage forgets a check | **Yes** — enforcement is centralised, not per-module |
| **The deployment owner deliberately forges an authorization record** | **No** — they own the database |

The last row is an explicit trust boundary: what stops it is the **legal authorization agreement**, which makes unauthorised scanning a breach as well as, in most jurisdictions, an offence. The authorization record's real value in that scenario is *evidentiary* — it records who authorised what, when, and under which ToS version, which is exactly what matters if a scan is ever disputed.

**Do not market this as "it cannot be pointed at someone else."** It cannot be pointed
at someone else *by its users*. Its operator is inside the trust boundary, and saying
otherwise would be a claim we cannot support.

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
  Cloudflare/AWS/etc., not the operator.
- `DEDICATED` → **full action set.**

### 2b. How a CIDR *earns* `DEDICATED` (ADR-0008)

An operator can list CIDRs on their authorization record. Listing is a **request,
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
- **Re-checked every run**, so a range the operator stops announcing drops back
  to HTTP-only automatically. Authorization is never trusted forever.

> **Known limitation.** Apex-ASN is a *proxy* for org ownership. A CDN-fronted
> apex announces the CDN's ASN, so such an operator's real origin block will not
> auto-confirm. That is deliberate (deny beats guess); those operators use the
> explicit `scan_shared_infra` opt-in instead.

**History:** this was a real vulnerability, not a hypothetical. `ip_scope` was
once stored verbatim from the request body, so a tenant could point a subdomain
they controlled at *any* IP, declare that block "dedicated", and unlock port
scanning of third-party infrastructure. Guard tests:
`tests/security/test_authorization_self_grant.py`,
`tests/unit/test_scope_confirmation.py`.

### 2c. `scan_shared_infra` — the explicit opt-in

An operator who genuinely owns the cloud their domain runs on can set
`scan_shared_infra` on the program. This extends the full action set to
`CLOUD_SHARED` / `PUBLIC` IPs. It **never** unlocks a third-party CDN edge, and
**never** overrides a hard-deny class.

### 2d. `scope_override` — waiving the engine outright

A second program setting, **off by default**, that does what `scan_shared_infra`
deliberately refuses to. With it on, for that program only:

| Gate | Normally | With `scope_override` |
|---|---|---|
| Host under a verified apex | required | **skipped** |
| Hard-denied classes (private, loopback, CGNAT, multicast, reserved) | refused | **reachable** |
| Link-local `169.254.0.0/16`, incl. the metadata address | refused | **still refused** |
| Third-party CDN edge | HTTP-layer only, never promotable | **full action set** |
| Unconfirmed public / cloud-shared | HTTP-layer only | **full action set** |
| Program's `excluded_hosts` / `excluded_cidrs` | refused | **still refused** |
| Politeness rate cap | applied | **still applied** |
| Verified + current authorization record | required to scan | **still required** |

**Why it exists.** The engine grants scope from what it can *prove*. An operator can
own infrastructure it cannot prove — hosts behind a CDN, an internal range, a cloud
block `asnmap` will not confirm against the apex's ASN. Refusing port scanning there
is the correct default and the wrong answer for someone scanning their own estate,
and §2b already concedes that anyone with database access can assert whatever they
like. This makes that assertion an explicit, logged setting instead of a Mongo write.

**What it costs, stated plainly.** One of those rows reaches past the operator's own
estate: a CDN edge is shared with that provider's other customers, so scanning one in
full is scanning infrastructure that is not theirs. That is what the switch means, not
a bug in it.

**The one thing it cannot buy** is link-local, and so `169.254.169.254`. Every other
hard-denied class describes the *target*, and whether to reach it is the operator's
call. That one describes *us*: it is the cloud metadata service of whatever host the
worker runs on, so reaching it would make ExactSurface an SSRF vector against its own
instance and report that instance's IAM credentials as a finding on someone else's
domain. Waiving it grants the operator no reach over their own estate, so it is not on
offer — see `NEVER_OVERRIDABLE` in `core/scope.py`. A mixed answer containing one is
refused whole, so a second A record cannot get around it.

**What keeps it honest.** Off by default and per-program, never global. Both edges log
at WARNING with the program, apex, actor and tenant. Exclusion lists outrank it,
because those are the operator's own instruction and an override that ignored them
would be a footgun with no use case. The Playground's ephemeral scope sets it to
`False` explicitly so the free-form waiver and this one can never compound.

Covered in `tests/unit/test_scope.py` (including that it defaults off, that it does
not leak between programs, and that it reaches the metadata address — asserted rather
than implied) and `tests/security/test_scope_override_api.py`.

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
This governs the requests ExactSurface itself makes at scanned hosts: the takeover
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
so `EXACTSURFACE_WORKER_FLEET_SIZE` **must be ≥ your real replica count**. In prod, a
worker that cannot reach a shared store refuses to start.

**Scanner subprocesses** (`core.ratelimit.derive_subprocess_rate`) — a token bucket
**cannot** govern a subprocess: naabu, httpx, katana, nuclei, feroxbuster and ffuf
each send their own traffic, so our limiter never sees it. The ceiling is handed to
the tool up front, via its rate flag (`-rate`/`-rl`/`--rate-limit`), derived from
the per-target cap. For a tool given many hosts at once the flag is an aggregate
(`cap × hosts`, clamped by an absolute ceiling); for a per-host invocation it is the
cap itself. Every derivation publishes `exactsurface_subprocess_per_target_pps{tool}`, so
the ceiling is verifiable per tool rather than asserted. See ADR-0009 (naabu) and
ADR-0013 (the rest).

> This was a live bug, twice over. First: `port_scan.py` called naabu without a
> rate, using naabu's flat `1000` default — **100× the cap** — while naabu's
> docstring wrongly claimed the limiter covered it (ADR-0009). Then an audit found
> the *other five* tools passed no rate flag at all: httpx/katana/nuclei ran at
> their 150 rps default (15× the cap) and feroxbuster/ffuf were unlimited. `-c` and
> `-t` look like rate controls but bound concurrency, not rate (ADR-0013).

**Verifiable, not asserted.** `/metrics` exposes
`exactsurface_politeness_rate_limit_pps` (the cap) and, per tool,
`exactsurface_subprocess_rate_pps{tool}` (aggregate) and
`exactsurface_subprocess_per_target_pps{tool}` (derived). The §15 exit gate is
"no subprocess exceeds the cap *verified by metrics*" — these are that evidence, and
`SubprocessRateExceedsPolitenessCap` pages if any tool crosses it. Tests:
`tests/unit/test_politeness_rate.py`, `tests/unit/test_subprocess_rate.py`.

Masscan is disabled in v1 (ADR-0004) and stays disabled until ExactSurface has
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

ExactSurface must never become a plaintext honeypot of *other companies'* live
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

## 10. Our own attack surface

We sell attack-surface management. Our own exposure is therefore not an ordinary
engineering concern — a breach of ours would be quoted back at us permanently. Two
things follow from that.

### 10.1 The product ships nothing it does not need

* **No debug or test endpoints in the API.** `test_product_api_has_no_devtools_surface`
  fails the build if a route ever contains `devtool`, `workbench` or `run-module`. A
  "temporary" testing endpoint is exactly how this class of exposure begins.
* **No unused binaries in the image.** Every tool installed must have a caller
  (`test_every_installed_binary_has_a_caller`). `cloudlist`, `notify` and `masscan` were
  removed on these grounds — an unused tool is both dead weight and a false claim.
* **Public signup closes after the first account** in prod (`public_signup_open`), so an
  exposed self-hosted deployment cannot have accounts created on it by a stranger.
* **Server-side validation everywhere.** Frontend validation is a convenience; every
  constraint is re-enforced in the API, because an operator with Burp is the baseline
  assumption, not the exception.

### 10.2 The Workbench is quarantined, not trusted

`devtools/` is an internal test bench that can call scanning functions **directly**,
bypassing the scope engine. That capability is legitimate for development and
unacceptable anywhere near an operator. It is contained by construction, not by policy:

| Control | Defeats |
|---|---|
| Adds **no endpoint** to the product API; imports modules in-process | An outsider finding or guessing a "dev" route — there is nothing to find |
| Per-run token (`token_urlsafe(32)`), constant-time compare, never persisted | Local processes and other users on the machine |
| `Host` allow-list (loopback only) | **DNS rebinding** — an attacker resolving their domain to `127.0.0.1` |
| `Sec-Fetch-Site` / `Origin` refusal of cross-site requests | **The real threat**: a website open in another tab driving the bench from the developer's own browser |
| Every rejection is `404`, never `401`/`403` | Confirming to a prober that something is there |
| `_assert_dev_only()` — `SystemExit` on `EXACTSURFACE_ENV=prod`, not flag-overridable | A configuration mistake exposing it |
| Explicit `COPY` lists + `.dockerignore` + tests | It reaching any shipped image |
| `introspect.resolve()` allow-list | The HTTP API being talked into importing `os:system` |

A loopback bind **alone would not be enough**, and that is the point worth remembering:
browsers will happily send cross-origin requests to `127.0.0.1`. Full detail and
rationale in [`docs/DEVTOOLS.md`](DEVTOOLS.md); the controls are asserted in
`tests/unit/test_devtools_security.py`.

---

## 11. No paid dependencies

Nothing in ExactSurface requires a commercial data source to function. Every module in
the default pipeline uses free, open-source tooling and public data.

A few **optional** modules can *use* a key if you have one, and are off by default with
that stated in the UI:

| Module | Optional key | Without it |
|---|---|---|
| Internet-index search (`uncover`) | Shodan / Censys / Fofa | module stays off |
| Search-engine exposure (`dork`) | Google CSE / Brave / SerpAPI | module stays off |
| Public code leaks (`github_osint`) | GitHub token (free tier is fine) | skipped — rate limits make it useless unauthenticated |

Breach-credential exposure is the one capability that would need a paid feed
(HaveIBeenPwned). **It is not built**, and it is not counted as coverage anywhere. If it
is added it will be opt-in with the operator's own key.

Parameter discovery uses **arjun** (MIT, free) as its primary engine, with a built-in
probe as the always-on fallback — the same pattern as trufflehog and the regex secret
detector, so a missing tool degrades the module rather than silently finding nothing.

---

## 12. Reporting a vulnerability

Email security@exactsurface.com with details and a reproduction. We trade in findings;
we take ours seriously.
