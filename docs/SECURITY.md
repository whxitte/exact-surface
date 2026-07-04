# Vantari Security Posture

Vantari is an outside-in scanner that holds sensitive data about customers'
attack surfaces. Its own security model matters as much as the findings it ships.

## Ethical boundary — detection only
Vantari **detects, it does not exploit** (§3.10). Operationally this means no
payload that modifies target state, causes denial of service, or exfiltrates data
beyond a minimal benign proof. Nuclei runs with `-etags dos,intrusive,fuzz`
excluded (`modules/scanning/nuclei.py`); aggressive/opt-in scanners only run
against confirmed-dedicated infrastructure.

## Authorization to scan
Nothing is scanned without a **current authorization record** for the program
(`db/authorizations.py`), created only after domain-ownership verification
(DNS-TXT or HTTP-file). This is the CFAA/CMA/Computer-Misuse defensibility
artifact, enforced at both the API scan-trigger and the worker dispatch.

## Central scope enforcement (the #1 control)
`core/scope.py` is non-bypassable: every network module obtains a `ScopeDecision`
before any I/O. It **denies by construction**:
- RFC1918, loopback, link-local (incl. the cloud metadata IP `169.254.169.254`),
  CGNAT, multicast, and reserved ranges — always, even if a verified subdomain
  resolves to one (DNS-rebinding guard);
- hosts outside a verified apex, or on the program exclusion list;
- CDN / cloud-shared IPs get **HTTP-layer probing only** — port scanning,
  content discovery, and active scanning require every resolved IP to be
  confirmed dedicated to the customer.

Exhaustively tested in `tests/unit/test_scope.py`; a failure there is a release
blocker.

## Tenant isolation
Multi-tenant from line one. Every document carries `tenant_id`; every query
filters by it; every compound index leads with it. The API resolves a `Principal`
and routes all program-scoped access through `require_program`, which scopes the
lookup to the caller's tenant — a valid token for tenant A receives **404** for
tenant B's resources (proven by `test_tenant_isolation`).

## Exposed-secret handling (§9c / ADR-0006)
When Vantari finds a customer's leaked secret it **never stores the plaintext**.
It keeps a masked hint (`AKIA••••7Q`), a keyed HMAC hash (for dedup, not
reversible from the DB alone), and a locator. Notifications and reports carry the
masked value only. Verified in `test_secrets.py`, `test_notify.py`,
`test_reports.py`.

## Application security
- Passwords: bcrypt. JWT: HS256 with rotating secret. API keys: shown once,
  stored as SHA-256 hash only.
- Per-**tenant** rate limiting (slowapi), not per-IP.
- Prod refuses to boot with insecure default secrets (`Settings.assert_prod_safe`).
- CORS locked to the frontend origin in prod; frontend ships no inline scripts.
- Trivy scans in CI (`.github/workflows/ci.yml`).
- Sentry ships **no PII** (`send_default_pii=False`).

## Compliance & retention
Findings 2y, raw scan output 90d, **raw secret evidence 30d** then purged to
masked+hash. Audit trail (`db/audit.py`) records scan runs. Scanning rate is
capped per target (`core/ratelimit.py`, ≤10/s default) to respect provider AUPs;
Masscan is disabled in v1 (ADR-0004).

## Reporting a vulnerability
Email security@vantari.io with details and a reproduction. We trade in findings;
we take ours seriously.
