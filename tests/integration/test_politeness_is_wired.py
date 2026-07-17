"""The politeness limiter is reachable from a real pipeline run (ADR-0012).

This is the regression guard for the bug itself. Every unit test of the limiter
passed while it was dead code: the bucket math was right, the Redis Lua was right,
and *nothing ever called it*. Correct components, never assembled.

So these assert the wiring, not the math. They are the tests that would have failed
when `RunContext` stopped being constructed and nobody noticed for a whole phase.
"""

from __future__ import annotations

from core.models import Asset
from core.ratelimit import InMemoryBucketStore, PolitenessLimiter, RateLimit
from core.scope import ProgramScope, default_engine
from core.tenant import TenantContext
from db.assets import AssetRepo
from pipelines.secrets import run_secret_scan
from pipelines.takeover import run_takeover
from tests.fakes import FakeMongo

ENGINE = default_engine()
TENANT = TenantContext(tenant_id="t1")
SCOPE = ProgramScope(verified_apexes=("example.com",))


class _CountingLimiter(PolitenessLimiter):
    """A real limiter that records what it was asked to pace."""

    def __init__(self) -> None:
        super().__init__(InMemoryBucketStore(), default_limit=RateLimit(1000.0, 1000.0))
        self.acquired: list[str] = []

    async def acquire(self, ip, asn=None, cost=1.0, limit=None, **kw):
        self.acquired.append(ip)
        return 0.0


async def _seed_asset(mongo, hostname="app.example.com"):
    await AssetRepo.from_mongo(mongo).upsert(
        Asset(
            tenant_id="t1",
            program_id="p1",
            fingerprint="a1",
            hostname=hostname,
            resolved_ips=["93.184.216.34"],
            dns_records={"cname": ["something.s3.amazonaws.com"]},
        )
    )


async def test_takeover_paces_its_probes_through_the_limiter():
    """run_takeover fetches customer hosts in-process. Before ADR-0012 it did so
    with no ceiling at all, however many hosts a program had."""
    mongo = FakeMongo()
    await _seed_asset(mongo)
    limiter = _CountingLimiter()
    fetched: list[str] = []

    async def fetch(url, *a, **k):
        fetched.append(url)
        return "NoSuchBucket"

    async def resolve(host, timeout=None):
        return ["93.184.216.34"]

    await run_takeover(
        mongo=mongo,
        engine=ENGINE,
        scope=SCOPE,
        tenant=TENANT,
        program_id="p1",
        timeout=5,
        fetch=fetch,
        resolve=resolve,
        limiter=limiter,
    )

    assert fetched, "test is vacuous — the stage made no requests"
    assert limiter.acquired, "requests went out WITHOUT passing the politeness limiter"


async def test_secret_scan_paces_its_fetches_through_the_limiter():
    """The secret fetcher pulls many URLs per host — the stage most likely to look
    like abuse from the target's side."""
    mongo = FakeMongo()
    await _seed_asset(mongo)
    await mongo.collection("endpoints").insert_one(
        {
            "tenant_id": "t1",
            "program_id": "p1",
            "url": "https://app.example.com/main.js",
            "hostname": "app.example.com",
        }
    )
    limiter = _CountingLimiter()
    fetched: list[str] = []

    async def fetch(url, *a, **k):
        fetched.append(url)
        return "var x = 1;"

    await run_secret_scan(
        mongo=mongo,
        engine=ENGINE,
        scope=SCOPE,
        tenant=TENANT,
        program_id="p1",
        hmac_key=b"k" * 32,
        fetch=fetch,
        limiter=limiter,
    )

    assert fetched, "test is vacuous — the stage fetched nothing to throttle"
    assert limiter.acquired == ["app.example.com"], "secret fetches bypassed the limiter"


async def test_a_pipeline_without_a_limiter_still_runs():
    """Dev and tests pass no limiter. That path must keep working — but it is the
    reason the omission went unnoticed, so it stays explicit."""
    mongo = FakeMongo()
    await _seed_asset(mongo)

    async def fetch(url, *a, **k):
        return "NoSuchBucket"

    async def resolve(host, timeout=None):
        return ["93.184.216.34"]

    result = await run_takeover(
        mongo=mongo,
        engine=ENGINE,
        scope=SCOPE,
        tenant=TENANT,
        program_id="p1",
        timeout=5,
        fetch=fetch,
        resolve=resolve,
    )
    assert result is not None
