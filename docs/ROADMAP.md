# Roadmap — the three biggest gaps

Not a wish list: these are the capabilities whose absence most often rules ExactSurface
out for a team that otherwise wants it. None is a research problem — each slots into
machinery that already exists (JWT auth + RBAC, `IntegrationSecretRepo`, `ApiKeyRepo`,
the SSRF-safe `guarded_post`, the arq worker). Ordered by how much each unblocks.

Contributions welcome. Read [`SECURITY.md`](SECURITY.md) first if the change touches a
control, and open an issue before starting something this size.

Grounding references (already in the codebase):
- Auth/identity: `api/routes/auth.py`, `api/deps.py` (`Principal`, `get_principal`,
  `_resolve_permissions`, `require_router_access`), `api/auth.py` (JWT).
- RBAC: `core/permissions.py`, `core/models.py` (`User`, `Group`, `Role`),
  `db/users.py`, `db/groups.py`, `api/routes/members.py`.
- Secrets/outbound: `db/integrations.py` (`IntegrationSecretRepo`),
  `modules/safe_http.py` (`guarded_post`), `api/routes/integrations.py`.
- Async work: `taskqueue/worker.py`, `taskqueue/arq_client.py`.

---

## 1. SSO / SAML + SCIM  — *effort: M · Enterprise feature*

**Why it blocks deals:** every mid-market+ security team mandates SSO before they'll
put staff in a tool. Today ExactSurface is email+password only.

### Scope
- **OIDC** for Okta / Entra ID / Google Workspace (covers ~90% of buyers), **plus SAML
  2.0** for the rest. Do OIDC first.
- **Per-tenant IdP config** (the tenant owner wires their own IdP), not one global IdP.
- **JIT provisioning:** a first-time SSO login creates the `User` in the tenant with **no
  groups** (consistent with the RBAC default — no access until the owner assigns a group).
- **SCIM 2.0** (phase 2) for automated user deprovisioning — the real enterprise ask is
  "when we offboard someone in Okta, they lose ExactSurface access."

### Data model (`core/models.py`)
- New `TenantSSOConfig(TenantScopedModel)`: `provider` (oidc|saml), `issuer`/`metadata_url`,
  `client_id`, `client_secret` (store via `IntegrationSecretRepo`, never plaintext),
  `allowed_email_domains: list[str]`, `default_group_ids: list[str]`, `enabled: bool`.
- `User` gains: `sso_subject: str | None` (IdP `sub`), `auth_provider: "local"|"sso"`.
  Keep email globally unique as today.

### API
- `api/routes/sso.py`:
  - `GET /sso/{tenant_slug}/login` → redirect to IdP (OIDC auth code + PKCE).
  - `GET /sso/{tenant_slug}/callback` → validate, find-or-JIT-create `User`, mint the
    **existing** JWT via `create_access_token(...)`. Reuse the whole downstream stack —
    `_resolve_permissions` already resolves groups per request, so SSO users flow through
    RBAC unchanged.
  - Owner-only config CRUD under the members/settings surface: `PUT /sso` (guard with
    `require_owner`, mirror `api/routes/members.py`).
- Add SSO config routes to the **owner-only** management surface; gate the *feature* on
  Enterprise plan via the existing plan check (`core/plans.py`).

### Security must-dos
- Validate `iss`/`aud`/`exp`/nonce/`state`; PKCE on the code flow.
- Bind the IdP identity to the tenant by `allowed_email_domains` — never let an SSO login
  land a user in the wrong tenant.
- `client_secret` and SAML keys go through `IntegrationSecretRepo` (masked, encrypted),
  never returned in reads (same contract as `api/routes/integrations.py`).
- SCIM endpoints authenticate with a dedicated bearer token, scoped to one tenant.

### Acceptance
- An Okta test app can log a user in; the JIT user has no access until grouped; disabling
  the user in Okta (SCIM) revokes access within one request cycle (permissions are live).

---

## 2. Ticketing integrations  — *effort: M · gate: Business+*

**Why it blocks deals:** "does it push to Jira?" is asked in nearly every eval. Findings
must land in the operator's workflow, not just a webhook/Slack ping.

### Scope
- **Jira Cloud** first (largest share), then **GitHub Issues**, **Linear**, **ServiceNow**.
- **Push:** create a ticket from a finding — manually ("Create ticket" on a finding) and
  by **rule** (e.g. auto-create for `critical`/`high` on a program).
- **De-dup & status sync (phase 2):** store the created ticket id on the finding; on
  re-detection don't re-create; when ExactSurface marks a finding `resolved`, comment/transition
  the ticket (and optionally the reverse).

### Data model
- Reuse `IntegrationSecretRepo` for creds (Jira API token, GH app token, etc.) — the
  `INTEGRATION_KEYS` registry already models this; add the ticketing providers there.
- New `TicketLink(TenantScopedModel)`: `finding_fingerprint`, `provider`, `external_id`,
  `url`, `status`, `created_at`. Or add `tickets: list[dict]` to the finding via a
  `PRESERVE_FIELDS`-style out-of-band write (same pattern as the 403-bypass `record_bypass`
  in `db/endpoints.py`, so a re-scan upsert never wipes it).
- Per-program rule: extend the alert-policy dict (`core/alert_policy.py`) with
  `ticket_provider` + `ticket_min_severity`.

### Modules & wiring
- `modules/ticketing/{jira,github,linear,servicenow}.py` — pure `create(finding, config)
  -> {external_id,url}` functions, injected transport for offline tests (mirror
  `modules/notification/base.py`).
- **All outbound HTTP through `modules/safe_http.guarded_post`** — an operator-supplied
  Jira base URL is an SSRF surface exactly like a webhook. Do not use a plain client.
- Auto-create runs in the notify pipeline / a dedicated arq task (reuse the
  `run_notify`/worker pattern), so ticket creation is async and never blocks a scan.
- `api/routes`: `POST /programs/{id}/findings/{fp}/ticket` (manual create; guard
  `programs.manage`); config under the settings surface (`settings.manage`).

### Acceptance
- A `critical` finding auto-creates a Jira issue with the finding's transparency payload
  (detector, matched request, repro) in the body; re-scan doesn't duplicate it; resolving
  in ExactSurface comments the issue.

---

## 3. Public REST API + docs  — *effort: S · gate: Business+*

**Why it blocks deals:** teams want to pull assets/findings into their own SIEM/dashboards
and automate. Most of this already exists — it needs versioning, docs, and key hygiene.

### Scope
- **Versioned surface:** mount the read/automation routes under `/v1/` with a stability
  promise. The data routers already exist; add the prefix + a deprecation policy.
- **Auth:** the `X-API-Key` path already works and — importantly — **an API key already
  inherits its creator's live RBAC permissions** (`_resolve_permissions` via `created_by`),
  so API access is correctly scoped for free. Just document it.
- **Rate limiting:** slowapi is already wired (`api/rate_limit.py`); add per-key limits and
  return `X-RateLimit-*` headers.
- **Docs:** FastAPI already generates OpenAPI — expose a curated `/v1/docs`, hide internal
  routes from the public schema (`include_in_schema=False`), and write a short "getting
  started + auth + pagination + examples" reference page in the dashboard.
- **Key management UX:** the settings API-keys card exists; add scoping display (which
  permissions the key carries), last-used, and one-click revoke.

### Security must-dos
- Public schema must exclude auth-internal and members/SSO admin routes.
- Enforce pagination limits server-side on list endpoints (cap `limit`; the body-size and
  input-validation hardening already landed — extend the same posture to query bounds).
- Keys are already SHA-256-hashed at rest (`ApiKey.key_hash`); keep raw-shown-once.

### Acceptance
- `curl -H "X-API-Key: …" https://…/v1/programs/{id}/findings` returns the caller's
  tenant data only, respects the key's RBAC scope, is rate-limited, and appears in `/v1/docs`.

---

## Sequencing & estimate

| Order | Item | Effort | Unblocks |
|------|------|--------|----------|
| 1 | Public REST API + docs | S | Business deals, "can we automate?" — cheapest win, mostly exposure |
| 2 | Ticketing (Jira → GH → Linear → ServiceNow) | M | Nearly every eval; do Jira, ship, iterate |
| 3 | SSO/OIDC (+ SAML, then SCIM) | M | Every enterprise deal; OIDC first, SCIM last |

**Cross-cutting:** all three reuse existing safety controls — `guarded_post` for outbound
SSRF safety, `IntegrationSecretRepo` for masked/encrypted creds, the live-resolved RBAC for
scoping, and the input-validation boundary (`core/validation.py`). Nothing here should
introduce a new plain HTTP client or a new unvalidated input — see
`docs/SECURITY.md` §9 and the architecture-decisions memory.
