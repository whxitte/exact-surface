"""The scheduler refreshes the shared scope feed, and never lets it break scheduling.

The scheduler is a singleton that is always up, so it is the natural owner of the
periodic feed refresh (ADR-0014) — exactly one process fetches. The hard requirement
is isolation: a refresh failing (network down, a provider 500, a collapsed feed
rejected) must never touch the scan-scheduling loop.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from core.config import Settings
from db.scope_feed import ScopeFeedRepo, feed_cidr_count
from taskqueue.scheduler import Scheduler
from tests.fakes import FakeMongo


def _scheduler(mongo, **overrides) -> Scheduler:
    settings = Settings(**overrides)
    return Scheduler(mongo, _noop_enqueue, settings=settings)


async def _noop_enqueue(job):
    pass


async def _fetch_ok():
    cloudfront = [{"ip_prefix": f"13.{i}.0.0/16", "service": "CLOUDFRONT"} for i in range(14)]
    ec2 = [{"ip_prefix": f"52.{i}.0.0/16", "service": "EC2"} for i in range(30)]
    cloudflare = "\n".join(f"104.{i}.0.0/16" for i in range(24)) + "\n"
    return {"prefixes": cloudfront + ec2}, cloudflare


async def test_refresh_is_due_on_the_first_call_then_throttled():
    mongo = FakeMongo()
    sched = _scheduler(mongo, scope_feed_refresh_hours=24)

    # monkeypatch the fetch by wrapping the module function via the scheduler path
    import scripts.update_scope_feeds as usf

    calls = {"n": 0}
    orig = usf.update_scope_feeds_to_mongo

    async def counting(m, *, fetch=None):
        calls["n"] += 1
        return await orig(m, fetch=_fetch_ok)

    usf.update_scope_feeds_to_mongo = counting
    try:
        now = datetime(2026, 7, 17, tzinfo=UTC)
        assert await sched.maybe_refresh_scope_feed(now) is True
        # 1 hour later — not due yet
        assert await sched.maybe_refresh_scope_feed(now + timedelta(hours=1)) is False
        # 25 hours later — due again
        assert await sched.maybe_refresh_scope_feed(now + timedelta(hours=25)) is True
    finally:
        usf.update_scope_feeds_to_mongo = orig

    assert calls["n"] == 2
    assert feed_cidr_count(await ScopeFeedRepo.from_mongo(mongo).get()) > 0


async def test_zero_hours_disables_the_refresh():
    sched = _scheduler(FakeMongo(), scope_feed_refresh_hours=0)
    assert await sched.maybe_refresh_scope_feed() is False


async def test_a_failing_refresh_is_swallowed():
    """A refresh blowing up must return False, not propagate — the caller runs it in
    the same try as run_once, and a raised error there would be logged as a failed
    scheduler tick."""
    mongo = FakeMongo()
    sched = _scheduler(mongo, scope_feed_refresh_hours=24)

    import scripts.update_scope_feeds as usf

    orig = usf.update_scope_feeds_to_mongo

    async def boom(m, *, fetch=None):
        raise ConnectionError("provider unreachable")

    usf.update_scope_feeds_to_mongo = boom
    try:
        assert await sched.maybe_refresh_scope_feed() is False
    finally:
        usf.update_scope_feeds_to_mongo = orig

    # nothing was written, and the scheduler is unharmed
    assert await ScopeFeedRepo.from_mongo(mongo).get() is None
