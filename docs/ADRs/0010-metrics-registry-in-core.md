# 0010 — The metrics registry lives in `core/`, not `daemon/`

Date: 2026-07-16
Status: Accepted

## Context

§4 places the metrics registry at `daemon/metrics.py`. That worked while only the
API rendered `/metrics`, but it quietly blocked instrumenting the thing that most
needed it.

The dependency direction is `api`/`pipelines`/`taskqueue` → `db` → `core`, with
`core` depending on nothing internal. That is what keeps `core` pure and
exhaustively unit-testable with zero mocks — the property the scope engine's
safety guarantees rest on.

`core/ratelimit.py` is the politeness limiter (§3.8b). To count allowed vs
throttled decisions it must reach the registry — but `core → daemon` inverts the
direction. The result: **the limiter shipped with no metrics at all**, and §7's
Phase D exit gate ("naabu never exceeds the global rate cap, *verified by
metrics*") had nothing to verify against. The only metric in the entire codebase
was `vantari_http_requests_total`.

So the layout forced a choice between an architectural violation and an
unobservable safety control. Both are bad.

## Decision

Move the registry to **`core/metrics.py`** and delete `daemon/metrics.py`.
Importers updated: `api/main.py`, `pipelines/port_scan.py`.

This is a deviation from §4's directory listing, recorded here per §17.

The justification is that the registry already satisfies `core`'s contract — it
is **pure in-memory state with no I/O**: a dict, a lock, and a text renderer, no
network, no disk, no DB. It reads as a `daemon` concern only because the
*exposition endpoint* is operational, but the endpoint lives in `api/main.py`
anyway; `daemon/` merely held the data structure.

It is also consumed by every layer — `core` (limiter decisions), `pipelines`
(scan rates), `api` (rendering). A shared, dependency-free primitive used by all
layers belongs at the bottom, not in a leaf.

Also added `observe()` (histograms) at the same time, since §15's latency targets
need distributions, not gauges.

## Consequences

**Good.** `core.ratelimit` now emits `vantari_politeness_decisions_total`
(`allowed`/`throttled`) and publishes the configured ceiling — the Phase D exit
gate has real evidence. `core` stays pure by its actual definition (no I/O), and
the dependency graph stays acyclic. Any future `core` policy can be instrumented
without an architectural argument.

**Cost.** §4's listing is now wrong until the spec is amended; this ADR is the
record. `daemon/` no longer owns metrics, which may surprise someone reading §4
first — hence the pointer in `docs/ARCHITECTURE.md`.

**Deliberately not done.** The limiter labels decisions **aggregate only**, with
no per-target label: a label per scanned IP would mint an unbounded number of time
series and take out the Prometheus instance. The `throttled:allowed` ratio is what
tells an operator the ceiling is working; identifying *which* target is a logging
concern, not a metrics one.

## Alternatives considered

- **Inject an observer callback into `PolitenessLimiter`.** Keeps `core` free of
  the import, but every construction site must remember to wire it or the metric
  silently vanishes — the same class of "looks instrumented, isn't" failure this
  is fixing. Rejected.
- **Emit from the call sites instead.** The allow/deny decision happens *inside*
  the limiter; callers only see the boolean. They would have to re-derive what the
  limiter already knows.
- **Adopt `prometheus_client`.** Its global registry would solve the layering by
  fiat, but adds a dependency for what is ~130 lines, and the existing renderer
  already matches the exposition format. Revisit if native histograms or exemplars
  are ever needed.
- **Leave it in `daemon/` and accept no limiter metrics.** The status quo. It
  failed an explicit spec exit gate.
