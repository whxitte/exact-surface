"""Distributing the scope feed via Mongo, with the bundled file as the floor (ADR-0014).

The feed classifies IPs as CDN/cloud-shared, which is what restricts ExactSurface to
HTTP-layer probing (§3.9). Storing it in Mongo lets an update reach the fleet without
a rebuild — but a feed that *loses* ranges is a removed protection, so every path
here fails toward the more-protective option: a missing, unreadable, or thin Mongo
copy falls back to the bundled file, never the reverse.
"""

from __future__ import annotations

import pytest

from core.scope import IpClass, ScopeEngine
from db.scope_feed import ScopeFeedRepo, build_scope_engine, feed_cidr_count
from scripts.update_scope_feeds import update_scope_feeds_to_mongo
from tests.fakes import FakeMongo

# A Cloudflare range from the bundled feed; classified CDN when the feed is loaded.
CF_IP = "104.16.5.5"


def _feed(providers) -> dict:
    return {"providers": providers}


def _big_feed() -> dict:
    """A feed strictly larger than the bundled baseline, so it is trusted on load."""
    baseline = feed_cidr_count(ScopeEngine.bundled_feed())
    extra = [f"203.0.{i}.0/24" for i in range(baseline + 5)]
    return _feed([{"name": "cloudflare", "class": "cdn", "cidrs": extra}])


# -- repo round-trip ---------------------------------------------------------
async def test_set_then_get_round_trips_the_feed():
    mongo = FakeMongo()
    repo = ScopeFeedRepo.from_mongo(mongo)
    assert await repo.get() is None  # nothing published yet

    feed = _feed([{"name": "cloudflare", "class": "cdn", "cidrs": ["104.16.0.0/13"]}])
    await repo.set(feed)
    got = await repo.get()
    assert got["providers"] == feed["providers"]


async def test_set_is_idempotent_single_document():
    mongo = FakeMongo()
    repo = ScopeFeedRepo.from_mongo(mongo)
    await repo.set(_feed([{"name": "a", "class": "cdn", "cidrs": ["1.1.1.0/24"]}]))
    await repo.set(_feed([{"name": "a", "class": "cdn", "cidrs": ["2.2.2.0/24"]}]))
    # one doc, latest wins
    assert (await repo.get())["providers"][0]["cidrs"] == ["2.2.2.0/24"]


# -- build_scope_engine: the file is the floor -------------------------------
async def test_empty_mongo_falls_back_to_the_bundled_file():
    engine = await build_scope_engine(FakeMongo())
    # The bundled feed classifies Cloudflare ranges → proves the file loaded.
    assert engine.classify_ip(CF_IP) == IpClass.CDN


async def test_a_valid_larger_mongo_feed_is_used():
    mongo = FakeMongo()
    await ScopeFeedRepo.from_mongo(mongo).set(_big_feed())
    engine = await build_scope_engine(mongo)
    assert engine.classify_ip("203.0.1.5") == IpClass.CDN  # a range only in the Mongo feed


async def test_a_thin_mongo_feed_is_rejected_for_the_bundled_file():
    """The updater only merges upward, so a Mongo copy below the bundled baseline is
    corruption. Trusting it would silently un-classify real CDN ranges."""
    mongo = FakeMongo()
    await ScopeFeedRepo.from_mongo(mongo).set(
        _feed([{"name": "x", "class": "cdn", "cidrs": ["203.0.1.0/24"]}])  # 1 cidr, way under
    )
    engine = await build_scope_engine(mongo)
    # falls back to bundled → still classifies Cloudflare, and does NOT trust the thin feed
    assert engine.classify_ip(CF_IP) == IpClass.CDN


async def test_a_mongo_read_error_falls_back_to_the_file():
    class Boom:
        def collection(self, _name):
            raise ConnectionError("mongo down")

    engine = await build_scope_engine(Boom())
    assert engine.classify_ip(CF_IP) == IpClass.CDN  # never crashes, never un-scopes


async def test_lab_allow_private_is_threaded_through():
    engine = await build_scope_engine(FakeMongo(), allow_private=True)
    # 10.x is private; with allow_private it is not hard-denied as a class.
    assert engine.classify_ip("10.1.2.3") == IpClass.PRIVATE


# -- the scheduled Mongo update ----------------------------------------------
async def _fetch_ok():
    """A realistic fetch: it REPLACES the managed providers (cloudflare, aws_*), so
    it must return counts comparable to the seeded baseline (cloudflare 22,
    cloudfront 13) or the shrink guard rejects it — which is the point of the guard."""
    cloudfront = [{"ip_prefix": f"13.{i}.0.0/16", "service": "CLOUDFRONT"} for i in range(14)]
    ec2 = [{"ip_prefix": f"52.{i}.0.0/16", "service": "EC2"} for i in range(30)]
    cloudflare = "\n".join(f"104.{i}.0.0/16" for i in range(24)) + "\n"
    return {"prefixes": cloudfront + ec2}, cloudflare


async def test_first_mongo_update_seeds_from_the_bundled_file():
    """Empty Mongo must not start from only what it fetched — that would drop the
    hand-maintained akamai/fastly/google/azure providers the image ships."""
    mongo = FakeMongo()
    feed = await update_scope_feeds_to_mongo(mongo, fetch=_fetch_ok)

    names = {p["name"] for p in feed["providers"]}
    assert {"akamai", "fastly", "google_cloud_lb", "azure_front_door"} <= names
    # persisted, and at least as large as the baseline
    assert feed_cidr_count(await ScopeFeedRepo.from_mongo(mongo).get()) >= feed_cidr_count(
        ScopeEngine.bundled_feed()
    )


async def test_a_rejected_mongo_update_leaves_the_stored_feed_untouched():
    mongo = FakeMongo()
    good = await update_scope_feeds_to_mongo(mongo, fetch=_fetch_ok)

    async def fetch_garbage():
        return {"prefixes": []}, ""  # cloudflare empty, aws empty → FeedRejected

    from scripts.update_scope_feeds import FeedRejected

    with pytest.raises(FeedRejected):
        await update_scope_feeds_to_mongo(mongo, fetch=fetch_garbage)

    assert (await ScopeFeedRepo.from_mongo(mongo).get())["providers"] == good["providers"]


async def test_update_then_build_engine_uses_the_new_ranges():
    """End to end: a scheduled update writes Mongo, and a freshly built engine (as a
    worker restart would build one) sees the new ranges."""
    mongo = FakeMongo()
    await update_scope_feeds_to_mongo(mongo, fetch=_fetch_ok)
    engine = await build_scope_engine(mongo)
    assert engine.classify_ip("13.5.0.1") == IpClass.CDN  # a CloudFront range we fetched
