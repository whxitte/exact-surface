"""The politeness ceiling actually applies, and survives a Redis outage (ADR-0012).

Background, because it explains why these tests are pointed the way they are: the
limiter was fully built, unit-tested, and **never called**. `RedisBucketStore` was
never constructed, `PolitenessLimiter.allow` had no callers outside its own tests,
and `RunContext.limiter` was a field on a dataclass nobody instantiated. Every
worker therefore ran an in-memory bucket that nothing consulted, and the two
pipelines that make in-process HTTP at customer hosts ran unthrottled.

So these do not test the bucket math (test_ratelimit.py does). They test that the
control is *reachable* and that its failure modes are the safe ones.
"""

from __future__ import annotations

import pytest

from core.ratelimit import (
    DegradingBucketStore,
    InMemoryBucketStore,
    PolitenessLimiter,
    RateLimit,
    throttled_fetch,
)

LIMIT = RateLimit(rate=10.0, burst=10.0)


class _BrokenStore:
    """A shared store that is down."""

    def __init__(self) -> None:
        self.calls = 0

    async def take(self, key, limit, cost, now):
        self.calls += 1
        raise ConnectionError("redis is gone")


class _RecordingStore:
    """Captures the limit it was asked to enforce."""

    def __init__(self, allow: bool = True) -> None:
        self.seen: list[RateLimit] = []
        self._allow = allow

    async def take(self, key, limit, cost, now):
        self.seen.append(limit)
        return self._allow


# -- degradation: never fail open, never hard-stop ---------------------------
async def test_redis_outage_does_not_raise():
    """A Redis blip must not surface as a failed scan stage."""
    store = DegradingBucketStore(_BrokenStore(), InMemoryBucketStore(), fleet_size=3)
    assert await store.take("h", LIMIT, 1.0, 0.0) is True  # degraded, still answering
    assert store.degraded is True


async def test_degraded_fallback_enforces_this_process_share_not_the_full_rate():
    """The point of the divisor. A local bucket is per-process, so N workers each
    running the FULL rate would emit N× the ceiling at the target. If this ever
    passes the undivided limit through, a Redis outage becomes an AUP breach."""
    fallback = _RecordingStore()
    store = DegradingBucketStore(_BrokenStore(), fallback, fleet_size=4)

    await store.take("h", LIMIT, 1.0, 0.0)

    assert fallback.seen[0].rate == pytest.approx(2.5)  # 10 / 4 workers
    assert fallback.seen[0].burst == pytest.approx(2.5)


async def test_degradation_never_lets_more_through_than_the_shared_store_would():
    """Fail-open check, stated as the invariant rather than the mechanism."""
    fallback = _RecordingStore()
    store = DegradingBucketStore(_BrokenStore(), fallback, fleet_size=2)
    await store.take("h", LIMIT, 1.0, 0.0)
    assert all(seen.rate <= LIMIT.rate for seen in fallback.seen)


async def test_recovery_returns_to_the_shared_store():
    """Degradation must be temporary — otherwise one blip permanently halves the
    fleet's throughput until someone restarts it."""
    primary = _RecordingStore()
    store = DegradingBucketStore(primary, _RecordingStore(), fleet_size=3)
    store._degraded = True

    await store.take("h", LIMIT, 1.0, 0.0)

    assert store.degraded is False
    assert primary.seen[0].rate == 10.0  # full shared ceiling again


async def test_fleet_size_must_be_sane():
    with pytest.raises(ValueError):
        DegradingBucketStore(_RecordingStore(), InMemoryBucketStore(), fleet_size=0)


# -- acquire: politeness costs time, not coverage ----------------------------
async def test_acquire_waits_instead_of_dropping_the_request():
    """`allow()` returning False means "skip it", which for a scanner silently drops
    a URL and reports a clean result. Politeness must slow the scan, not shrink it."""
    slept: list[float] = []

    async def fake_sleep(d):
        slept.append(d)

    limiter = PolitenessLimiter(InMemoryBucketStore(), default_limit=RateLimit(1.0, 1.0))
    await limiter.acquire("h", sleep=fake_sleep)  # burst token
    waited = await limiter.acquire("h", sleep=fake_sleep)  # must wait, not give up

    assert slept, "acquire returned without waiting for budget"
    assert waited > 0


async def test_acquire_gives_up_waiting_rather_than_hanging_a_stage():
    """Bounded: a wedged bucket must not hold a stage past its timeout. Overshooting
    by one request beats a stage-wide timeout that loses every finding."""
    slept = []

    async def fake_sleep(d):
        slept.append(d)

    limiter = PolitenessLimiter(InMemoryBucketStore(), default_limit=RateLimit(1.0, 0.0))
    waited = await limiter.acquire("h", sleep=fake_sleep, max_wait=2.0)
    assert waited <= 2.0 + 1.0  # bounded, and it returned at all


# -- the wrapper is what makes the control reachable -------------------------
async def test_throttled_fetch_paces_every_request():
    calls: list[str] = []
    acquired: list[str] = []

    async def fetch(url):
        calls.append(url)
        return "body"

    class _Limiter:
        async def acquire(self, host, *a, **k):
            acquired.append(host)
            return 0.0

    wrapped = throttled_fetch(fetch, _Limiter())
    assert await wrapped("https://app.example.com/main.js") == "body"

    assert calls == ["https://app.example.com/main.js"]
    assert acquired == ["app.example.com"]  # keyed on host, not the full URL


async def test_throttled_fetch_buckets_by_host_so_one_host_cannot_hide_behind_paths():
    acquired: list[str] = []

    async def fetch(url):
        return ""

    class _Limiter:
        async def acquire(self, host, *a, **k):
            acquired.append(host)
            return 0.0

    wrapped = throttled_fetch(fetch, _Limiter())
    for path in ("/a.js", "/b.js", "/c.js"):
        await wrapped(f"https://app.example.com{path}")

    assert acquired == ["app.example.com"] * 3  # same bucket every time
