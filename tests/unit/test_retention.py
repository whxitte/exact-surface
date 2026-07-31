"""Retention purge — the plan limit that is also a security control."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from scripts.retention import (
    MIN_RETENTION_DAYS,
    PROTECTED,
    PURGEABLE,
    cutoff_for,
    purge_tenant,
)
from tests.fakes import FakeMongo

NOW = datetime(2026, 8, 1, tzinfo=UTC)


async def _seed(mongo, collection: str, tenant: str, *, age_days: int, field: str) -> None:
    await mongo.collection(collection).insert_one({
        "tenant_id": tenant,
        field: NOW - timedelta(days=age_days),
        "_id": f"{collection}-{age_days}",
    })


async def test_expired_records_are_deleted_and_current_ones_kept():
    mongo = FakeMongo()
    await _seed(mongo, "findings", "t1", age_days=400, field="last_seen")
    await _seed(mongo, "findings", "t1", age_days=5, field="last_seen")
    result = await purge_tenant(mongo, "t1", 180, now=NOW)
    assert result.deleted.get("findings") == 1
    left = await mongo.collection("findings").find({}).to_list(None)
    assert len(left) == 1


async def test_a_record_re_confirmed_last_night_survives_however_old_it_is():
    """The window applies to last_seen, not first_seen. A finding re-observed by
    yesterday's scan is current information whatever its discovery date."""
    mongo = FakeMongo()
    await mongo.collection("findings").insert_one({
        "tenant_id": "t1",
        "first_seen": NOW - timedelta(days=900),
        "last_seen": NOW - timedelta(days=1),
    })
    result = await purge_tenant(mongo, "t1", 30, now=NOW)
    assert result.total == 0


async def test_purge_never_crosses_tenants():
    mongo = FakeMongo()
    await _seed(mongo, "findings", "t1", age_days=400, field="last_seen")
    await _seed(mongo, "findings", "t2", age_days=400, field="last_seen")
    await purge_tenant(mongo, "t1", 30, now=NOW)
    survivors = await mongo.collection("findings").find({}).to_list(None)
    assert [s["tenant_id"] for s in survivors] == ["t2"]


async def test_assets_and_authorizations_are_never_purged():
    """Deleting an asset because it is old would make the product forget what the
    customer owns and re-report it as new tomorrow. Authorizations are the legal record
    that a scan was permitted."""
    mongo = FakeMongo()
    for collection in ("assets", "authorizations", "programs"):
        await mongo.collection(collection).insert_one({
            "tenant_id": "t1", "last_seen": NOW - timedelta(days=5000),
        })
    await purge_tenant(mongo, "t1", 30, now=NOW)
    for collection in ("assets", "authorizations", "programs"):
        assert await mongo.collection(collection).find({}).to_list(None), collection


def test_protected_and_purgeable_never_overlap():
    assert not (set(PURGEABLE) & PROTECTED), "a collection is both purgeable and protected"


def test_a_corrupt_retention_value_cannot_wipe_the_database():
    """Even the cheapest tier keeps a month. A zero or negative value must not become
    'delete everything'."""
    for junk in (0, -1, -9999):
        assert cutoff_for(junk, NOW) == NOW - timedelta(days=MIN_RETENTION_DAYS)


async def test_dry_run_counts_without_deleting():
    mongo = FakeMongo()
    await _seed(mongo, "findings", "t1", age_days=400, field="last_seen")
    result = await purge_tenant(mongo, "t1", 30, now=NOW, dry_run=True)
    assert result.deleted.get("findings") == 1
    assert await mongo.collection("findings").find({}).to_list(None)


async def test_higher_tier_keeps_data_a_lower_tier_would_have_purged():
    """The point of the limit: retention is something customers pay for."""
    mongo = FakeMongo()
    for tenant in ("free_t", "biz_t"):
        await _seed(mongo, "findings", tenant, age_days=200, field="last_seen")
    await purge_tenant(mongo, "free_t", 30, now=NOW)
    await purge_tenant(mongo, "biz_t", 365, now=NOW)
    survivors = {f["tenant_id"] for f in await mongo.collection("findings").find({}).to_list(None)}
    assert survivors == {"biz_t"}


@pytest.mark.parametrize("collection", sorted(PURGEABLE))
async def test_every_purgeable_collection_is_actually_reachable(collection: str):
    """A collection named in PURGEABLE that does not exist is a typo that would silently
    never purge — exactly the class of bug this suite exists to prevent."""
    mongo = FakeMongo()
    field = PURGEABLE[collection]
    await _seed(mongo, collection, "t1", age_days=5000, field=field)
    result = await purge_tenant(mongo, "t1", 30, now=NOW)
    assert result.deleted.get(collection) == 1, f"{collection} was not purged via {field}"
