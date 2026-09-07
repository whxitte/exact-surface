# 0006 — Exposed-secret handling: never store plaintext
Date: 2026-07-04
Status: Accepted

## Context
When ExactSurface finds an operator's leaked secret (`.env`, an API key in JS, a GitHub
leak), naively storing the plaintext turns ExactSurface's own database into a
high-value honeypot holding *other companies'* live credentials — a catastrophic
liability and breach magnet.

## Decision
Plaintext secrets are **never persisted**. For each exposed secret we store: a
**masked** hint (`AKIA••••7Q`), a **keyed hash** (HMAC with an app-tier key, for
dedup only — not reversible from the DB alone), and a **locator** (URL/file:line).
Any retained raw snippet is **envelope-encrypted** and purged after
`retention_raw_secret_days` (default 30). Notifications carry the masked value and
locator only, never the secret. The full value is revealed in the UI only to
authorized tenant users via an audited, time-boxed action.

## Consequences
- A DB compromise does not leak operators' live credentials.
- Dedup/idempotency still work (via the keyed hash) without the plaintext.
- `core/hashing.secret_fingerprint` and `core/secrets_policy` (Phase B) implement
  the masking/hashing; `core/config.secret_hash_key` provides the HMAC key,
  which must live outside the database.

## Alternatives considered
- **Store plaintext, encrypt at rest only.** Rejected: still exposes secrets to
  anyone with DB/app access and lengthens the blast radius; masking + short raw
  retention is far safer.
