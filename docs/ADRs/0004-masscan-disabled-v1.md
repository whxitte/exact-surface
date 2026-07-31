# 0004 — Masscan disabled in v1; naabu with a global rate cap
Date: 2026-07-04
Status: Accepted

## Context
Running a mass port scanner from shared cloud infrastructure (DigitalOcean, AWS,
GCP) violates provider Acceptable Use Policies and draws abuse reports from
targets' ISPs. The realistic outcome is account termination — which takes the
entire platform down with it.

## Decision
**Masscan is not shipped in v1.** Its registry entry is `enabled=False` and the binary
is not installed in the scanning image. Port discovery uses **naabu** with a rate cap
and bounded concurrency, behind the global politeness limiter (§3.8b, ≤10 pkt/s per
target IP by default). Masscan returns only once ExactSurface operates from dedicated,
abuse-contact-registered netblocks.

## Consequences
- We lose the "fastest possible port sweep" differentiator in v1, and keep the
  platform (and cloud account) alive — the right trade.
- Scope engine (§3.9) additionally restricts port scanning to confirmed-dedicated
  IPs, so naabu never runs against CDN/cloud-shared ranges.

### Correction (2026-07-31)
This ADR previously said the image still installed `masscan` so that re-enabling was
"a config change", gated on `EXACTSURFACE_MASSCAN_ENABLED`. That was not true: no
masscan wrapper was ever written, so nothing read the flag and setting it to `true`
did nothing. The binary and the flag have both been removed rather than left as a
switch that silently does nothing. Bringing masscan back means writing
`modules/ports/masscan.py`, installing the binary, and having dedicated netblocks —
a real piece of work, which is the honest thing for this ADR to say.

## Alternatives considered
- **Masscan at low rate.** Still trips provider egress heuristics and offers no
  advantage over naabu once rate-capped.
