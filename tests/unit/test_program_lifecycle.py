"""Program delete-with-purge + per-asset / per-program monitoring toggles."""

from __future__ import annotations

from core.models import Asset, Finding, Program
from core.severity import Severity
from db.assets import AssetRepo
from db.findings import FindingRepo
from db.programs import ProgramRepo, delete_program_and_data
from tests.fakes import FakeMongo


def _asset(fp="a1", hostname="api.acme.com", program_id="p1"):
    return Asset(
        tenant_id="t1",
        program_id=program_id,
        fingerprint=fp,
        hostname=hostname,
        resolved_ips=["1.2.3.4"],
    )


async def test_monitored_defaults_true_and_survives_rescan():
    mongo = FakeMongo()
    repo = AssetRepo.from_mongo(mongo)
    await repo.upsert(_asset())
    assert (await repo.get("t1", "a1"))["monitored"] is True

    # user mutes it, then the scanner re-observes the same asset (upsert again)
    assert await repo.set_monitored("t1", "a1", False) is True
    await repo.upsert(_asset())  # a normal re-scan must NOT re-enable it
    assert (await repo.get("t1", "a1"))["monitored"] is False


async def test_set_monitored_unknown_asset_returns_false():
    mongo = FakeMongo()
    assert await AssetRepo.from_mongo(mongo).set_monitored("t1", "nope", False) is False


async def test_delete_program_purges_all_scoped_data():
    mongo = FakeMongo()
    await ProgramRepo.from_mongo(mongo).save(
        Program(tenant_id="t1", program_id="p1", apex_domain="acme.com")
    )
    await AssetRepo.from_mongo(mongo).upsert(_asset())
    await FindingRepo.from_mongo(mongo).upsert(
        Finding(
            tenant_id="t1",
            program_id="p1",
            fingerprint="f1",
            check_id="x",
            module="nuclei",
            location="https://acme.com",
            name="thing",
            severity=Severity.LOW,
        )
    )
    # a second program's data must be untouched
    await AssetRepo.from_mongo(mongo).upsert(_asset(fp="a2", program_id="p2"))

    await delete_program_and_data(mongo, "t1", "p1")

    assert await ProgramRepo.from_mongo(mongo).get("t1", "p1") is None
    assert await AssetRepo.from_mongo(mongo).count("t1", "p1") == 0
    assert await FindingRepo.from_mongo(mongo).count("t1", "p1") == 0
    assert await AssetRepo.from_mongo(mongo).count("t1", "p2") == 1  # other program safe


async def test_delete_is_tenant_scoped():
    mongo = FakeMongo()
    await AssetRepo.from_mongo(mongo).upsert(_asset())
    # different tenant deleting the same program_id must not touch t1's data
    await delete_program_and_data(mongo, "t2", "p1")
    assert await AssetRepo.from_mongo(mongo).count("t1", "p1") == 1
