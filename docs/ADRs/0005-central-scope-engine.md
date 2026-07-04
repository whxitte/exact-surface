# 0005 — Central, non-bypassable scope engine
Date: 2026-07-04
Status: Accepted

## Context
An EASM platform that scans the wrong thing — an internal IP, a cloud metadata
endpoint, a CDN it doesn't own, a host outside the customer's verified scope — is
a legal and operational catastrophe. Scattering these checks across modules
guarantees one will be forgotten.

## Decision
All scope logic lives in one pure module, `core/scope.py`. Every network-touching
module obtains a `ScopeDecision` from it *before* any I/O. The engine denies by
construction: RFC1918, loopback, link-local (incl. the metadata IP
169.254.169.254), CGNAT, multicast, and reserved ranges are always refused — even
if a verified subdomain resolves to one (a DNS-rebinding guard). Hosts outside a
verified apex, or on the exclusion list, are refused. CDN/cloud-shared IPs get
HTTP-layer probing only; the full action set requires every resolved IP to be
confirmed dedicated to the customer.

## Consequences
- Safety is testable: `tests/unit/test_scope.py` exhaustively proves the denials,
  and a failure there is a release blocker.
- The engine is pure (no DNS/DB); the async `assert_in_scope` wrapper injects the
  resolver, keeping the decision logic I/O-free and fully unit-testable.
- Adding a module cannot accidentally widen scope — the decision is computed by
  the worker and handed to the module as a restricted action set.

## Alternatives considered
- **Per-module allowlist checks.** Rejected: unauditable and fragile; one missed
  check is a breach.
