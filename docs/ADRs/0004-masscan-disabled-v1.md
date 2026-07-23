# 0004 — Masscan disabled in v1; naabu with a global rate cap
Date: 2026-07-04
Status: Accepted

## Context
Running a mass port scanner from shared cloud infrastructure (DigitalOcean, AWS,
GCP) violates provider Acceptable Use Policies and draws abuse reports from
targets' ISPs. The realistic outcome is account termination — which takes the
entire platform down with it.

## Decision
**Masscan is disabled in v1** (`EXACTSURFACE_MASSCAN_ENABLED=false`, and its registry
entry ships `enabled=False`). Port discovery uses **naabu** with a rate cap and
bounded concurrency, behind the global politeness limiter (§3.8b, ≤10 pkt/s per
target IP by default). Masscan returns only once ExactSurface operates from dedicated,
abuse-contact-registered netblocks.

## Consequences
- We lose the "fastest possible port sweep" differentiator in v1, and keep the
  platform (and cloud account) alive — the right trade.
- The image still installs the `masscan` binary so re-enabling is a config change
  once dedicated infrastructure exists; it is inert until then.
- Scope engine (§3.9) additionally restricts port scanning to confirmed-dedicated
  IPs, so naabu never runs against CDN/cloud-shared ranges.

## Alternatives considered
- **Masscan at low rate.** Still trips provider egress heuristics and offers no
  advantage over naabu once rate-capped.
