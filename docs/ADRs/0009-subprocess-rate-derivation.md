# 0009 — Politeness for scanner subprocesses (a token bucket can't reach naabu)

Date: 2026-07-16
Status: Accepted

## Context

§3.8b requires a **global politeness limiter** capping ExactSurface at
**≤10 packets/requests per second per target IP**, "regardless of how many jobs
touch it concurrently". `core/ratelimit.py` implements exactly that: a token
bucket keyed on `(target-ip, asn)`, Redis-backed so the ceiling holds across the
worker fleet.

It did not apply to the port scanner, and could not:

- **naabu is a subprocess.** It opens its own sockets and sends its own packets.
  Our limiter is Python code in the worker process; naabu's traffic never passes
  through it. A token bucket can only govern I/O that flows through the bucket.
- `naabu.scan_ports` defaulted to `rate: int = 1000`, and
  `pipelines/port_scan.py` called `await naabu(scannable, timeout)` — never
  passing a rate. So port scans ran at **1000 pps: 100× the cap** for a
  single-host scan.
- `naabu.py`'s own docstring asserted "the global politeness limiter still caps
  total packets per target IP (§3.8b)". That was false and actively misleading —
  it is why the gap survived review.

This is the §7 Phase D exit gate: *"naabu never exceeds the global rate cap
(verified by metrics)"*. It was failing on both halves — the cap wasn't enforced,
and there were no metrics to verify it with (the only metric in the codebase was
`exactsurface_http_requests_total`).

## Decision

Recognise **two** politeness mechanisms, because there are two kinds of I/O:

1. **In-process I/O** → the existing token bucket (`PolitenessLimiter`).
   Unchanged.
2. **Scanner subprocesses** → the ceiling is *computed and handed to the tool*
   before exec, via pure `core.ratelimit.subprocess_rate_for(host_count, cap,
   ceiling=1000)`.

naabu's `-rate` is process-wide and spread across its targets, so N targets at
`cap` each is an aggregate of `cap × N`. That is the derivation. It is clamped by
an absolute `ceiling` so a huge target list can't turn "polite per target" into a
massive aggregate egress from our own network. It never returns 0 (that would
stall a scan) and treats 0/negative host counts as one target.

`pipelines/port_scan.py` derives the rate, passes it, and publishes:

- `exactsurface_politeness_rate_limit_pps` — the configured cap
- `exactsurface_port_scan_rate_pps` — the aggregate handed to naabu
- `exactsurface_port_scan_per_target_pps` — the derived per-target rate

The exit gate says *verified by metrics*, so the per-target number an operator can
graph against the cap **is** the deliverable — not an assertion in a docstring.

## Consequences

**Good.** The documented ceiling is now the enforced ceiling. It is observable in
Grafana. The naabu docstring now states the truth: `-rate` is the only control
that applies to it, and callers must derive it from the cap.

**Cost.** Port scans are slower — deliberately. 30 hosts at a 10/s cap is 300 pps
aggregate rather than 1000. Politeness is the product requirement (§15 targets
zero AUP complaints); speed is not.

**Approximation, stated honestly.** naabu spreads `-rate` across its targets but
does not guarantee a perfectly even per-target distribution, so `cap × N` bounds
the *average*, not a hard per-target instantaneous ceiling. It is a ~100×
improvement over the status quo and the right shape; a hard per-target guarantee
would need per-target invocations (N subprocesses) or a packet-level shaper —
revisit if a target ever complains.

**Generalises.** Any future scanner subprocess (masscan, if dedicated netblocks
ever arrive) uses the same helper rather than inventing its own default.

## Alternatives considered

- **Route naabu through the token bucket.** Impossible without a packet-level
  interception layer; naabu doesn't call our code.
- **One naabu invocation per target, gated by the bucket.** A true per-target
  guarantee, but N subprocess spawns and loses naabu's batching. Revisit if the
  averaging proves insufficient.
- **Leave `-rate` at 1000 and rely on the scope engine.** The scope engine limits
  *which* IPs may be scanned, not *how fast*. Orthogonal control; doesn't address
  AUP.
