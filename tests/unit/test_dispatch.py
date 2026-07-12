"""Pipeline dispatch — routing + auth gating (no network; empty-data pipelines)."""

from __future__ import annotations

import pytest

from core.errors import AuthorizationRequired
from core.models import Authorization, Program
from core.scope import ScopeEngine
from core.tenant import TenantContext
from db.authorizations import AuthorizationRepo
from db.programs import ProgramRepo
from pipelines.dispatch import run_pipeline
from tests.fakes import FakeMongo

ENGINE = ScopeEngine.from_data_file()
TENANT = TenantContext("t1", "u1")


async def _seed(mongo, *, authorize=True):
    await ProgramRepo.from_mongo(mongo).save(
        Program(tenant_id="t1", program_id="p1", apex_domain="customer.com", verified=True)
    )
    if authorize:
        await AuthorizationRepo.from_mongo(mongo).save(
            Authorization(tenant_id="t1", program_id="p1", authorized_by="u1", apex_verified=True)
        )


async def _run(mongo, pipeline):
    return await run_pipeline(
        mongo=mongo,
        engine=ENGINE,
        tenant=TENANT,
        program_id="p1",
        pipeline=pipeline,
        timeout=10,
        hmac_key=b"k",
    )


async def test_routes_probe_pipeline():
    # probe with no assets makes no tool/network calls and returns its shape
    mongo = FakeMongo()
    await _seed(mongo)
    res = await _run(mongo, "probe")
    assert "probeable" in res and res["alive"] == 0


async def test_routes_port_scan_pipeline():
    mongo = FakeMongo()
    await _seed(mongo)
    res = await _run(mongo, "port_scan")
    assert "scannable" in res and res["ports"] == 0


async def test_probe_with_no_assets_is_skipped_not_success():
    mongo = FakeMongo()
    await _seed(mongo)
    res = await _run(mongo, "probe")
    assert res["skipped"] is True and "no assets" in res["note"]
    run = await mongo.collection("scan_runs").find_one({"program_id": "p1"})
    assert run["status"] == "skipped" and run["note"]


async def test_whole_program_scan_skipped_while_one_is_running():
    from datetime import UTC, datetime

    from core.models import ScanRun, ScanStatus
    from db.audit import ScanRunRepo

    mongo = FakeMongo()
    await _seed(mongo)
    # a genuinely-alive whole-program scan is already in flight
    await ScanRunRepo.from_mongo(mongo).save(
        ScanRun(
            tenant_id="t1",
            scan_id="live",
            program_id="p1",
            pipeline="scan",
            status=ScanStatus.RUNNING,
            started_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
    )
    res = await _run(mongo, "scan")
    assert res["skipped"] is True and "already running" in res["note"]


async def test_cascade_scan_not_blocked_by_running_whole_program_scan():
    from datetime import UTC, datetime

    from core.models import ScanRun, ScanStatus
    from db.audit import ScanRunRepo

    mongo = FakeMongo()
    await _seed(mongo)
    await ScanRunRepo.from_mongo(mongo).save(
        ScanRun(
            tenant_id="t1",
            scan_id="live",
            program_id="p1",
            pipeline="scan",
            status=ScanStatus.RUNNING,
            started_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
    )
    # a targeted (cascade) run for a new host is small + important → not blocked
    res = await run_pipeline(
        mongo=mongo,
        engine=ENGINE,
        tenant=TENANT,
        program_id="p1",
        pipeline="scan",
        timeout=10,
        hmac_key=b"k",
        targets=("new.customer.com",),
    )
    assert res.get("note") != "scan already running"  # ran (empty-data → its own result)


async def test_github_osint_without_token_is_skipped():
    mongo = FakeMongo()
    await _seed(mongo)
    res = await _run(mongo, "github_osint")  # no GITHUB token in test settings
    assert res["skipped"] is True and "token" in res["note"].lower()
    run = await mongo.collection("scan_runs").find_one({"program_id": "p1"})
    assert run["status"] == "skipped"


async def test_notify_without_channels_is_skipped():
    mongo = FakeMongo()
    await _seed(mongo)
    res = await _run(mongo, "notify")
    assert res["skipped"] is True
    run = await mongo.collection("scan_runs").find_one({"program_id": "p1"})
    assert run["status"] == "skipped" and "channel" in run["note"].lower()


async def test_unknown_pipeline_raises():
    mongo = FakeMongo()
    await _seed(mongo)
    with pytest.raises(ValueError, match="unknown pipeline"):
        await _run(mongo, "does-not-exist")


async def test_missing_program_refused():
    with pytest.raises(AuthorizationRequired):
        await _run(FakeMongo(), "probe")


async def test_unauthorized_program_refused():
    mongo = FakeMongo()
    await _seed(mongo, authorize=False)
    with pytest.raises(AuthorizationRequired):
        await _run(mongo, "probe")
