# 0011 — Every process exposes its own `/metrics`, served by the stdlib

Date: 2026-07-17
Status: Accepted

## Context

ADR-0010 moved the registry into `core/` so the politeness limiter could
instrument itself. That fixed *emission*. It did not fix *exposition*, and the gap
between the two was invisible.

`core.metrics.MetricsRegistry` is plain in-memory state — a dict, a lock, a
renderer. It is therefore **per process**. `/metrics` is rendered by
`api/main.py`, so the API's registry is scrapeable. But the API image is
deliberately slim and carries no scan toolchain (§3.8): **no scanning happens in
the API process**. Every metric that describes scanning — `exactsurface_scan_stage_*`,
`exactsurface_scan_run_*`, `exactsurface_politeness_decisions_total`,
`exactsurface_port_scan_*`, `exactsurface_alert_latency_seconds` — is emitted in the
**worker**, which arq runs with no HTTP server at all.

So those samples accumulated in worker memory and were discarded at exit. Nothing
errored. A Grafana panel built on them would have rendered empty forever, and
`§15`'s "naabu never exceeds the global rate cap (*verified by metrics*)" would
have had a metric that no one could ever read. This is the same "looks
instrumented, isn't" failure ADR-0010 set out to kill, one layer further out.

The scheduler had a sharper version of the problem: it emitted nothing at all,
while being the single process whose silent death stops *all* scanning.

## Decision

**Each process exposes its own registry; Prometheus scrapes all of them.** This is
the standard multi-process Prometheus pattern. `daemon/metrics_server.py` provides
the listener for the headless roles (worker, scheduler) on
`EXACTSURFACE_METRICS_PORT` (default 9100); the API keeps serving its own from FastAPI.
`deploy/prometheus.yml` scrapes all three roles, using `dns_sd_configs` for the
worker so each replica becomes its own target rather than whichever one DNS
happened to return.

**The listener is stdlib `http.server` on a daemon thread**, not aiohttp. Two
reasons. First, every aiohttp import in this codebase is function-local because
aiohttp is a runtime dependency absent from the test venv; a module-level import
would have broken collection, and the alternative — lazy-importing a *server* —
makes it untestable. Second and more substantive: a worker's event loop spends
most of its life awaiting blocking scan subprocesses, which is precisely when an
operator most wants the scrape to answer. A separate thread stays responsive
regardless. The endpoint serves one text page per scrape interval, so an event
loop buys nothing. `MetricsRegistry` is already `threading.Lock`-guarded
(`render()` included), so cross-thread reads are safe.

**The scheduler now emits `exactsurface_scheduler_last_success_timestamp`.**
`run_forever` deliberately swallows tick exceptions so one bad tick cannot kill
the loop — meaning a scheduler failing *every* tick keeps a live process and an
answering port while never enqueueing again. No liveness probe can distinguish
that from healthy-and-idle. `time() - <gauge>` can, and catches the crashed case
too.

## Consequences

**Good.** The Phase D/§15 rate-cap evidence is now actually readable, and Phase G's
"7 days unattended" gate has the two signals it needs: is scanning alive
(scheduler gauge), and is it quietly degrading (stage failure/timeout rates).
Dashboards and alerts are provisioned from git, and
`tests/unit/test_dashboard_queries.py` asserts every panel and rule references a
metric something actually emits.

**Cost.** Counters are per-process and reset on restart — `rate()` handles that,
but *absolute* counter values are per-replica and must be `sum()`ed across
targets. Alert thresholds in `deploy/alerts.yml` duplicate values from
`core.config.Settings` because Prometheus cannot read app config; only the
politeness cap is currently pinned by a test.

**Bounded exposure.** The listener binds `0.0.0.0` (ruff S104, suppressed with
justification at the call site) because a peer container must reach it. It is
bounded deliberately: no host port is published for it in compose, the handler has
two read-only routes and nothing mutating, and **no metric carries a tenant,
program, or host label** — which also keeps cardinality flat. The container
network is the boundary. Running a worker directly on a shared host means passing
`host="127.0.0.1"`.

**Fails open, quietly.** A bind failure logs a warning and returns `None` rather
than raising: metrics must never be why a worker fails to start. Trading all
scanning for a dashboard is the wrong direction.

## Alternatives considered

- **Pushgateway.** The documented use is batch jobs pushing terminal state. These
  are live counters owned by long-running processes; the gateway would turn them
  into stale-on-death samples and add infrastructure to hide a liveness signal we
  specifically want.
- **Write metrics to Redis so the API renders a merged view.** Redis is already
  there, and it would give one scrape target. But it makes `core.metrics` do I/O,
  which reverses ADR-0010's whole justification, and it invents a bespoke
  aggregation protocol where Prometheus already has one.
- **`prometheus_client` with `multiprocess` mode.** Solves this by fiat, but it is
  built for forked workers sharing a directory, not separate containers — it would
  not have helped across the worker/scheduler/API split, which is the actual
  topology.
- **Have the worker log metrics and scrape the logs.** Turns a numeric time series
  into a parsing problem.
- **Static compose targets for the worker.** Silently scrapes one replica and
  under-reports the fleet. Rejected in favour of DNS discovery.
