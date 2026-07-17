"""Cloud-bucket exposure pipeline (module 18) — wiring + signal-quality policy."""

from __future__ import annotations

from core.tenant import TenantContext
from db.findings import FindingRepo
from pipelines.cloud_buckets import run_cloud_buckets
from tests.fakes import FakeMongo

TENANT = TenantContext(tenant_id="t1")


def _checker(status_by_substring: dict[str, int]):
    """Return a checker that answers by matching a substring of the URL."""

    async def check(url: str) -> int | None:
        for needle, status in status_by_substring.items():
            if needle in url:
                return status
        return 404  # no such bucket

    return check


async def test_public_bucket_becomes_a_high_finding():
    mongo = FakeMongo()
    res = await run_cloud_buckets(
        mongo=mongo,
        tenant=TENANT,
        program_id="p1",
        apex="acme.com",
        checker=_checker({"acme-backup.s3": 200}),
    )
    assert res["public"] == 1 and res["new"] == 1

    findings = await FindingRepo.from_mongo(mongo).list("t1", "p1", limit=10)
    assert len(findings) == 1
    f = findings[0]
    assert f["severity"] == "high"
    assert f["check_id"] == "exposed-cloud-bucket"
    assert "acme-backup" in f["name"]
    assert f["location"].startswith("https://acme-backup.s3.amazonaws.com")
    assert f["reproduction"].startswith("curl")


async def test_attribution_caveat_is_stated_in_the_finding():
    """A bucket matching the domain label may not be the customer's — the finding
    must say so rather than imply proof of ownership."""
    mongo = FakeMongo()
    await run_cloud_buckets(
        mongo=mongo,
        tenant=TENANT,
        program_id="p1",
        apex="acme.com",
        checker=_checker({"acme.s3": 200}),
    )
    f = (await FindingRepo.from_mongo(mongo).list("t1", "p1", limit=10))[0]
    assert "NOT verified" in f["description"]


async def test_existing_but_private_bucket_is_counted_not_persisted():
    """403 = 'some bucket with a similar name exists'. Unattributable noise — it
    must not become a finding (§15 signal quality)."""
    mongo = FakeMongo()
    res = await run_cloud_buckets(
        mongo=mongo,
        tenant=TENANT,
        program_id="p1",
        apex="acme.com",
        checker=_checker({"acme-backup.s3": 403, "acme-dev.s3": 403}),
    )
    assert res["private"] == 2
    assert res["public"] == 0 and res["new"] == 0
    assert await FindingRepo.from_mongo(mongo).list("t1", "p1", limit=10) == []


async def test_no_buckets_found_is_clean():
    mongo = FakeMongo()
    res = await run_cloud_buckets(
        mongo=mongo, tenant=TENANT, program_id="p1", apex="acme.com", checker=_checker({})
    )
    assert res == {"checked": 0, "public": 0, "private": 0, "new": 0}


async def test_unreachable_provider_is_not_a_bucket():
    """A checker returning None (DNS failure/timeout) means 'no bucket', not a hit."""
    mongo = FakeMongo()

    async def none_checker(_url: str) -> int | None:
        return None

    res = await run_cloud_buckets(
        mongo=mongo, tenant=TENANT, program_id="p1", apex="acme.com", checker=none_checker
    )
    assert res["checked"] == 0


async def test_rerun_is_idempotent():
    mongo = FakeMongo()
    kw = dict(
        mongo=mongo,
        tenant=TENANT,
        program_id="p1",
        apex="acme.com",
        checker=_checker({"acme-backup.s3": 200}),
    )
    first = await run_cloud_buckets(**kw)
    second = await run_cloud_buckets(**kw)
    assert first["new"] == 1
    assert second["new"] == 0  # is_new fires exactly once
    assert len(await FindingRepo.from_mongo(mongo).list("t1", "p1", limit=10)) == 1


async def test_probes_all_three_providers():
    seen: list[str] = []

    async def recording(url: str) -> int | None:
        seen.append(url)
        return 404

    await run_cloud_buckets(
        mongo=FakeMongo(), tenant=TENANT, program_id="p1", apex="acme.com", checker=recording
    )
    assert any("s3.amazonaws.com" in u for u in seen)
    assert any("storage.googleapis.com" in u for u in seen)
    assert any("blob.core.windows.net" in u for u in seen)
    # the domain label only — never the full apex as a bucket name
    assert all("acme.com" not in u.split("//")[1].split(".")[0] for u in seen)
