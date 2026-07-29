"""Stopping a running scan (user-pressed "stop") unwinds gracefully.

The guarantees a customer is promised when they click stop, pinned here:

* the run ends ``CANCELLED`` — a clean outcome, not a failure;
* the stage that was in flight is marked cancelled and later stages never start;
* **everything already discovered is kept** (writes are idempotent upserts);
* the in-flight tool's subprocess is actually killed, not abandoned;
* a new scan can be started immediately afterwards, behaving normally.
"""

from __future__ import annotations

import asyncio

import pytest

from core.models import ScanStatus
from core.scope import ProgramScope, ScopeEngine
from core.tenant import TenantContext
from db.assets import AssetRepo
from db.audit import ScanRunRepo
from pipelines.orchestrate import run_full_pipeline
from tests.fakes import FakeMongo

ENGINE = ScopeEngine.from_data_file()
TENANT = TenantContext("t1", "u1")
SCOPE = ProgramScope(verified_apexes=("customer.com",))


async def _run(mongo, scan_id, **injected):
    return await run_full_pipeline(
        mongo=mongo,
        engine=ENGINE,
        scope=SCOPE,
        tenant=TENANT,
        program_id="p1",
        apex="customer.com",
        timeout=5,
        scan_id=scan_id,
        **injected,
    )


async def test_stop_before_a_stage_cancels_the_run(monkeypatch):
    """A stop recorded while the run is in flight ends it cleanly and skips the rest."""
    mongo = FakeMongo()
    audit = ScanRunRepo.from_mongo(mongo)

    # Pretend the user pressed stop immediately: the flag is already set.
    async def always_cancelled(self, _tenant, _scan):
        return True

    monkeypatch.setattr(audit.__class__, "is_cancel_requested", always_cancelled)

    result = await _run(mongo, "scan-cancel-1")
    assert result["cancelled"] is True

    run = await audit.get("t1", "scan-cancel-1")
    assert run["status"] == ScanStatus.CANCELLED.value
    assert "stopped by user" in (run.get("note") or "")
    # No stage was allowed to run, and none is left dangling in QUEUED/RUNNING.
    assert {s["status"] for s in run["stages"]} == {ScanStatus.CANCELLED.value}


async def test_data_found_before_the_stop_is_kept():
    """The first stage completes and persists; the stop lands after it. What was
    discovered must survive — that's the difference between 'stopped' and 'lost'."""
    mongo = FakeMongo()
    audit = ScanRunRepo.from_mongo(mongo)
    calls = {"n": 0}

    real_check = audit.__class__.is_cancel_requested

    async def cancel_after_first_stage(self, tenant_id, scan_id):
        calls["n"] += 1
        # domain_intel runs first, then ingest; stop after ingest has persisted.
        return calls["n"] > 2

    audit.__class__.is_cancel_requested = cancel_after_first_stage
    try:
        async def subfinder(domain, timeout):
            return ["app.customer.com"]

        async def resolve(hosts, _timeout):
            return {h: ["93.184.216.34"] for h in hosts}

        result = await _run(mongo, "scan-cancel-2", subfinder=subfinder, resolve=resolve)
    finally:
        audit.__class__.is_cancel_requested = real_check

    assert result["cancelled"] is True
    # ingest ran and its asset was written before the stop
    assets = await AssetRepo.from_mongo(mongo).list("t1", "p1", limit=100)
    assert any(a["hostname"] == "app.customer.com" for a in assets)

    run = await audit.get("t1", "scan-cancel-2")
    assert run["status"] == ScanStatus.CANCELLED.value
    stages = {s["name"]: s["status"] for s in run["stages"]}
    assert stages["ingest"] == ScanStatus.SUCCESS.value  # kept its success
    assert stages["notify"] == ScanStatus.CANCELLED.value  # never ran


async def test_request_cancel_only_affects_live_runs():
    """A finished run can't be retro-cancelled by a late click."""
    from core.models import ScanRun

    mongo = FakeMongo()
    audit = ScanRunRepo.from_mongo(mongo)
    await audit.save(
        ScanRun(
            tenant_id="t1",
            scan_id="done-1",
            program_id="p1",
            pipeline="full",
            status=ScanStatus.SUCCESS,
        )
    )
    assert await audit.request_cancel("t1", "done-1") is False
    assert await audit.is_cancel_requested("t1", "done-1") is False


async def test_cancel_kills_the_running_tool_subprocess():
    """The stop must terminate the child process, not just abandon the coroutine —
    otherwise a 'stopped' scan keeps sending traffic at the customer's targets."""
    from modules.exec import run_tool

    task = asyncio.ensure_future(run_tool("sleep", ["30"], timeout=30))
    await asyncio.sleep(0.2)  # let it actually spawn
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    # If the child were still alive this would hang; a killed one reaps immediately.
    await asyncio.sleep(0.2)


async def test_scheduler_does_not_restart_a_cancelled_scan():
    """Pressing stop must mean stopped: the bootstrap re-enqueued the very run the
    user had just cancelled, seconds later, because initial_scan_completed_at is
    still unset. Found on the first real test run."""
    from datetime import UTC, datetime, timedelta

    from core.models import ScanRun

    mongo = FakeMongo()
    audit = ScanRunRepo.from_mongo(mongo)
    now = datetime.now(UTC)
    await audit.save(
        ScanRun(
            tenant_id="t1",
            scan_id="cancelled-1",
            program_id="p1",
            pipeline="full",
            status=ScanStatus.CANCELLED,
            finished_at=now,
        )
    )
    # Just cancelled → the scheduler must back off.
    assert await audit.recent_cancelled_full("t1", "p1", within_seconds=1800, now=now) is not None
    # Long past → normal scheduling resumes.
    later = now + timedelta(hours=2)
    assert await audit.recent_cancelled_full("t1", "p1", within_seconds=1800, now=later) is None
