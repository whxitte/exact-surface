"""Idempotency + is_new-exactly-once tests — the core of §3.2.

If these regress, Vantari would either alert repeatedly on unchanged assets or
lose new-asset alerts. Both are product-defining bugs.
"""

from __future__ import annotations

from core.hashing import asset_fingerprint
from core.models import Asset, Finding
from db.assets import AssetRepo
from db.findings import FindingRepo
from tests.fakes import FakeMongo


def _asset(ips, fp="fp-a"):
    return Asset(
        tenant_id="t1", program_id="p1", fingerprint=fp,
        hostname="app.customer.com", resolved_ips=ips,
    )


async def test_first_upsert_inserts_second_is_noop():
    repo = AssetRepo(FakeMongo().collection("assets"))
    r1 = await repo.upsert(_asset(["45.55.1.1"]))
    r2 = await repo.upsert(_asset(["45.55.1.1"]))
    assert r1.inserted is True
    assert r2.inserted is False
    assert await repo.count("t1") == 1  # no duplicate row


async def test_is_new_fires_once_then_is_cleared():
    coll = FakeMongo().collection("assets")
    repo = AssetRepo(coll)
    await repo.upsert(_asset(["45.55.1.1"]))
    doc = await repo.get("t1", "fp-a")
    assert doc["is_new"] is True

    # consumer clears it, then the asset is re-observed
    await repo.clear_is_new("t1", ["fp-a"])
    await repo.upsert(_asset(["45.55.1.1"]))
    doc = await repo.get("t1", "fp-a")
    assert doc["is_new"] is False  # must NOT re-fire on re-observation


async def test_volatile_field_updates_but_first_seen_is_immutable():
    repo = AssetRepo(FakeMongo().collection("assets"))
    await repo.upsert(_asset(["45.55.1.1"]))
    first = await repo.get("t1", "fp-a")

    await repo.upsert(_asset(["45.55.9.9"]))  # IP changed → volatile update
    second = await repo.get("t1", "fp-a")

    assert second["resolved_ips"] == ["45.55.9.9"]
    assert second["first_seen"] == first["first_seen"]  # immutable
    assert second["last_seen"] >= first["last_seen"]    # volatile, bumped


async def test_upsert_many_counts_new_only():
    repo = AssetRepo(FakeMongo().collection("assets"))
    a = _asset(["1.1.1.1"], fp=asset_fingerprint("p1", "a.customer.com"))
    b = _asset(["1.1.1.2"], fp=asset_fingerprint("p1", "b.customer.com"))
    total, new = await repo.upsert_many([a, b, a])  # a appears twice
    assert (total, new) == (3, 2)


async def test_tenant_isolation_in_reads():
    coll = FakeMongo().collection("assets")
    repo = AssetRepo(coll)
    await repo.upsert(Asset(tenant_id="t1", program_id="p1", fingerprint="x",
                            hostname="a.customer.com"))
    await repo.upsert(Asset(tenant_id="t2", program_id="p1", fingerprint="x",
                            hostname="a.customer.com"))
    assert await repo.count("t1") == 1
    assert await repo.count("t2") == 1
    assert (await repo.get("t1", "x"))["tenant_id"] == "t1"


async def test_finding_upsert_roundtrip():
    repo = FindingRepo(FakeMongo().collection("findings"))
    f = Finding(tenant_id="t1", program_id="p1", fingerprint="ff",
                check_id="exposed-env", module="nuclei",
                location="https://app.customer.com/.env", name="Exposed .env")
    r = await repo.upsert(f)
    assert r.inserted
    doc = await repo.get("t1", "ff")
    assert doc["severity"] == "info" and doc["state"] == "new"  # enums stored as values
