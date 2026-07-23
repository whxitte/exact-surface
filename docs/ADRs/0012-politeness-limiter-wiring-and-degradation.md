# 0012 — Wire the politeness limiter for real, and degrade it safely

Date: 2026-07-17
Status: Accepted

## Context

The politeness limiter was **dead code**. Not half-built — fully built, carefully
tested, and never called.

Discovered while implementing §7 Phase G's "rate-limit graceful degradation", which
turned out to be impossible to do meaningfully on a limiter nothing invoked:

- `RedisBucketStore` — the store whose entire purpose is sharing the ceiling across
  the fleet — was **never constructed anywhere** outside its own tests.
- `taskqueue.worker.build_limiter(settings)` defaulted to `InMemoryBucketStore` and
  `startup()` never passed anything else. Every worker had a private bucket.
- `PolitenessLimiter.allow()` / `require()` had **no callers** in `pipelines/`,
  `modules/`, or `taskqueue/`.
- `ctx["limiter"]` was assigned in worker startup and never read.
- `modules.base.RunContext` carries a `limiter` field. Nothing constructs a
  `RunContext`.

Consequences of that, in order of severity:

1. **The in-process HTTP that ExactSurface aims at customer hosts was unthrottled.**
   `pipelines/takeover.py` (a body fetch per resolving host) and
   `pipelines/secrets.py` (many JS/config URLs per host) go straight out at
   `asyncio.gather` concurrency with no ceiling whatsoever.
2. **Even had it been called, the ceiling would have been per-process.** With
   `replicas: 2` in compose and `worker.replicas: 3` in Helm, N workers each
   enforcing "10 pps per target" locally emit up to 30 pps at a third party. §3.8b
   requires the ceiling to hold *regardless of how many concurrent jobs touch a
   target*.
3. **`RedisBucketStore` had a latent correctness bug** that only mattered once it
   was used: `allow()` passed `time.monotonic()`, whose epoch is arbitrary and
   **per process**. Feeding that into a shared bucket compares timestamps from
   different processes with unrelated origins — the refill math is meaningless.
4. Three docstrings asserted the opposite of the code: `core/ratelimit.py` said the
   Redis store was "shared across the worker fleet in production",
   `taskqueue/worker.py` said the fleet "passes a RedisBucketStore" and that the
   worker "hands the module a RunContext carrying ... the shared politeness
   limiter". This is the same failure as naabu's docstring claiming the limiter
   covered it (ADR-0009): the comment describing the intent, the code never
   acquiring it.

Every unit test passed throughout. They tested the bucket math, which was correct.
Nothing tested that the control was *reachable*, because the defect is an absence.

## Decision

**1. Call it.** The pipelines already inject their `fetch` function (that is how
they stay offline-testable), so `core.ratelimit.throttled_fetch(fetch, limiter)`
wraps at the injection point. `takeover` and `secrets` — the only two stages that
make in-process requests at customer hosts — pass through it. The limiter threads
`worker → run_program/run_pipeline → stage`. In `run_full_pipeline` the parameter
is **explicit rather than left to `**injected`**, so a swallowed kwarg cannot
silently mean "unthrottled" again.

**2. Share the ceiling.** `build_limiter` moves to `core/ratelimit.py` (it is pure
construction, no I/O — the ADR-0010 argument; it also makes it importable without
arq, and therefore testable at all) and builds a Redis-backed store when given a
client. The worker passes arq's pool. **In prod, a missing shared store now refuses
to start** rather than silently degrading to per-process buckets: not scanning is
recoverable, an AUP breach that terminates the cloud account is not. Same
fail-closed stance as `Settings.assert_prod_safe()`.

**3. Use Redis's clock.** The Lua script reads `redis.call('TIME')` and ignores the
caller's `now`. A shared bucket needs a shared clock and neither client-side option
works: `monotonic()` is not comparable across processes at all, and `time.time()`
is comparable but skewed — a worker 5s fast computes 5s of refill on its first call
and bursts straight through the ceiling. Redis is one authoritative clock with no
skew by construction. (Non-deterministic commands are fine: Redis has replicated
scripts by effect since 5.0, and compose pins redis 7.)

**4. Degrade, don't fail open or hard-stop.** `DegradingBucketStore` wraps the
shared store. On any primary error it falls back to a **local bucket at
`rate / worker_fleet_size`**. The division is the entire point: a local bucket is
per-process, so N workers each running the full rate would emit N× the ceiling —
the bug above, re-created by the fallback. Dividing means that even if the whole
fleet degrades simultaneously the aggregate stays within the cap. It scans slower
than strictly necessary when only one worker has degraded, which is the right way
to be wrong.

**5. Wait, don't drop.** `PolitenessLimiter.acquire()` is added and is what scan
traffic uses. `allow()` returning False means "skip this request", which for a
scanner silently removes a URL from coverage and reports a clean result —
politeness must cost *time*, not findings. `acquire` bounds its wait (`max_wait`,
default 60s) and proceeds rather than dropping: overshooting by one request beats
hanging a stage past its timeout and losing every finding in it.

## Consequences

**Good.** §3.8b is actually enforced for the traffic it can govern, and holds across
the fleet. §7's "rate-limit graceful degradation" is real. The dashboard's
politeness panel and the `PolitenessThrottlingSustained` alert can now show data —
**they could not have before**, since `allow()` was never invoked; the metric name
existed in unreachable code, which is exactly why
`test_dashboard_queries.py` (which checks names against source) passed and gave
false comfort.

**`worker_fleet_size` is a duplicated constant.** It must be `>=` the real replica
count or the degraded guarantee is void. Nothing enforces that automatically —
scale workers, update the setting. Default 3 matches the Helm chart.

**Bucketed by host, not IP.** `throttled_fetch` keys on the URL host. Two hosts on
one IP get a bucket each, which under-throttles shared infrastructure relative to a
strict per-IP reading of §3.8b. Resolving inside the wrapper would add a DNS round
trip per request, and the callers already hold scope-checked hostnames. Port
scanning, where per-IP matters most, is capped by naabu's derived `-rate`
(ADR-0009) instead.

**Still unthrottled by this limiter, by nature:** every subprocess tool. httpx,
katana, feroxbuster, ffuf and nuclei send their own packets and are bounded only by
their own rate flags. A token bucket in this process cannot govern them — the
ADR-0009 problem, and each tool needs its own audit. **This ADR does not close
that.**

**Untested against real Redis.** The Lua path, including `TIME`, is exercised only
against a fake. `redis.call('TIME')` in a script and the `evalsha` arity change want
verification against a live redis 7 before the unattended run.

## Alternatives considered

- **Fail open when Redis is down.** Silently removes the ceiling; a blip becomes an
  AUP breach. Never.
- **Fail closed (deny all) when Redis is down.** Safe, and the simplest thing that
  is not wrong — but a Redis blip stops all scanning, which is the outage §7's
  "graceful degradation" exists to prevent.
- **Local bucket at the full rate when degraded.** Re-creates the N× bug the moment
  it triggers, and only under the failure conditions nobody is watching.
- **Have modules take the limiter and self-police.** The `RunContext` design already
  tried this and is precisely how it rotted: a contract every new module must
  remember to honour, whose omission is invisible. Wrapping the injected fetch makes
  the ceiling apply by construction.
- **Delete the limiter as dead code.** Defensible on the evidence — but it would
  leave in-process requests at customer hosts permanently unthrottled and §3.8b
  unimplementable.
