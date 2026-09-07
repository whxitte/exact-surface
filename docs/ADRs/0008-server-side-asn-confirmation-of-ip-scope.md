# 0008 — Server-side ASN confirmation of authorization IP scope

Date: 2026-07-16
Status: Accepted

## Context

§9b says a resolved IP must be confirmed as the operator's — "via WHOIS/ASN
ownership matching the operator's verified org (via `asnmap`), recorded in the
authorization record" — before it may be port-scanned or aggressively probed.

The implementation didn't do that. `AuthorizationCreate.ip_scope` accepted full
`IpScopeEntry` objects (`cidr`, `ip_class`, `action_set`, `confirmed_via`) and
stored them verbatim. `build_program_scope` then fed every entry with
`ip_class == "dedicated"` into `authorized_dedicated_cidrs`, which
`ScopeEngine.evaluate` treats as full-action. `confirmed_via` was free text that
nothing read, and module 17 (`asn_mapper`) — the thing meant to do the confirming
— was never called by any pipeline.

**The exploit:** a tenant verifies a domain they genuinely own, points
`x.their-domain.com` at any IP on the internet, POSTs an authorization declaring
that IP's /24 `"ip_class": "dedicated"`, and ExactSurface port-scans and aggressively
probes third-party infrastructure on their behalf. DNS control is trivially
obtained; it proves nothing about IP ownership. This is precisely the scenario
§9b exists to prevent, and it is an AUP/legal risk (§15 targets zero AUP
complaints), not merely a bug.

Constraint discovered while fixing: **the API host has no `asnmap`.**
`Dockerfile.api` is `python:3.11-slim`; only `Dockerfile.pipeline` (the worker)
carries the toolchain, and §3.8 explicitly keeps the API slim and separate. So
confirmation cannot happen in the request path.

## Decision

Split *requesting* from *granting*, and put the grant on the worker.

1. **The API cannot grant.** `AuthorizationCreate.ip_scope` is `list[str]` —
   plain CIDRs. The server records them `pending`, HTTP-layer-only. The client
   has no way to express `ip_class` / `action_set` / `confirmed_via`; the old
   object form is a `422`.
2. **The worker confirms.** `pipelines.orchestrate.confirm_authorization_ip_scope`
   runs before scope construction on every full run: it resolves the verified
   apex's announced ASN ranges via `asnmap`, decides each requested CIDR
   (`core.scope.confirm_ip_scope`), and writes the verdict back onto the
   authorization record (§5d — the confirmation is part of the auditable
   artifact).
3. **Only a server marker is trusted.** `build_program_scope` honours an entry
   only when `core.scope.is_asn_confirmed` holds — `ip_class == "dedicated"`
   **and** `confirmed_via` starts with `asnmap:`. A class alone is insufficient.
4. **A CDN edge is never promotable**, even when the ASN matches:
   `evaluate()` computes `in_dedicated_cidr = cls != IpClass.CDN and (addr in
   dedicated_nets)`. Defence in depth against a bad or stale entry.
5. **Fail safe.** asnmap missing/timeout/error ⇒ nothing confirmed. Losing ASN
   data must never *grant* access.
6. **Re-confirm every run**, so a range the operator stops announcing decays back
   to HTTP-only automatically.

## Consequences

**Good.** Self-attestation can no longer unlock aggressive scanning. The
confirmation is auditable and revocable. Confirmation lives where the toolchain
already is, so the API image stays slim per §3.8.

**Cost.** An `asnmap` call per full run (cacheable later if it hurts).

**Accepted limitation.** Apex-ASN is a *proxy* for org ownership, not a proof of
it. A CDN-fronted apex announces the CDN's ASN, so that operator's real origin
block will not auto-confirm and stays HTTP-only. We accept a false-negative
(under-scanning) over a false-positive (scanning someone else's network). Those
operators use the explicit `scan_shared_infra` opt-in.

**Test note.** `test_build_program_scope_extracts_dedicated_cidrs` had *encoded
the vulnerability* — it asserted a client-supplied `confirmed_via="whois:AS14061"`
should be honoured. It was rewritten into an asnmap-confirmed case plus a
self-declared-is-ignored regression guard. A green test was certifying the hole.

## Alternatives considered

- **Confirm in the API.** Rejected: requires `asnmap` on the API image,
  contradicting §3.8, and puts a subprocess in the request path.
- **Async "pending confirmation" job.** More moving parts than confirming inline
  on the worker, which already runs per scan and must re-check anyway.
- **Match on org name via `asnmap -org`.** We don't reliably know the operator's
  legal org name; the apex's ASN is the signal we actually have.
- **Trust the operator's attestation + ToS.** This is what we had. A signature
  doesn't stop the packets, and the abuse report lands on us.

## Note (2026-08-01): organisation-name lookup

`asnmap` can also resolve an **organisation name** to its announced ranges, which is the
natural fallback for a CDN-fronted apex whose real origin ASN a domain lookup cannot
reach — the limitation this ADR records.

A `map_org()` wrapper existed for a while, unwired. It has been removed: unreachable
code that documents an intention is still unreachable code, and this ADR is the right
place for the intention. If the fallback is built, add the wrapper back **with its
caller in the same commit**, and treat it as gating DEDICATED (full-scan) promotion —
so it needs the same server-side confirmation as the domain path, not a shortcut.
