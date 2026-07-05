"""Stale scan-run reaper: orphaned RUNNING runs are closed out as FAILED.

A worker killed mid-run leaves its ScanRun stuck ``RUNNING`` forever; the reaper
sweep (run each scheduler tick) marks any run older than the threshold as
FAILED("orphaned") so the activity feed reflects reality.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from core.models import Authorization, Program, ScanRun, ScanStage, ScanStatus
from db.audit import ScanRunRepo
from db.authorizations import AuthorizationRepo
from db.programs import ProgramRepo
from taskqueue.scheduler import Scheduler
from tests.fakes import FakeMongo

NOW = datetime(2026, 7, 5, 12, 0, 0, tzinfo=UTC)


async def _save(mongo, *, scan_id, status, started_at, tenant="t1"):
    await ScanRunRepo.from_mongo(mongo).save(
        ScanRun(
            tenant_id=tenant,
            scan_id=scan_id,
            # distinct program_id per run: FakeMongo keys docs by program_id before
            # scan_id, so shared ids would collide (real Mongo keys on scan_id).
            program_id=scan_id,
            pipeline="full",
            status=status,
            started_at=started_at,
        )
    )


async def test_reaps_only_stale_running_runs():
    mongo = FakeMongo()
    repo = ScanRunRepo.from_mongo(mongo)
    # stale RUNNING (2h old) → reaped
    await _save(
        mongo, scan_id="stale", status=ScanStatus.RUNNING, started_at=NOW - timedelta(hours=2)
    )
    # fresh RUNNING (5m old) → left alone
    await _save(
        mongo, scan_id="fresh", status=ScanStatus.RUNNING, started_at=NOW - timedelta(minutes=5)
    )
    # old but already SUCCESS → not touched
    await _save(
        mongo, scan_id="done", status=ScanStatus.SUCCESS, started_at=NOW - timedelta(hours=5)
    )

    reaped = await repo.reap_stale(3600, now=NOW)
    assert reaped == 1

    runs = {r["scan_id"]: r for r in await repo.list("t1", limit=100)}
    assert runs["stale"]["status"] == ScanStatus.FAILED.value
    assert runs["stale"]["error"] == "orphaned"
    assert runs["stale"]["finished_at"] == NOW
    assert runs["fresh"]["status"] == ScanStatus.RUNNING.value
    assert runs["done"]["status"] == ScanStatus.SUCCESS.value


async def test_reaper_closes_out_non_terminal_stages():
    mongo = FakeMongo()
    repo = ScanRunRepo.from_mongo(mongo)
    await repo.save(
        ScanRun(
            tenant_id="t1",
            scan_id="s1",
            program_id="p1",
            pipeline="full",
            status=ScanStatus.RUNNING,
            started_at=NOW - timedelta(hours=2),
            stages=[
                ScanStage(name="ingest", status=ScanStatus.SUCCESS),
                ScanStage(name="probe", status=ScanStatus.RUNNING),
                ScanStage(name="scan", status=ScanStatus.QUEUED),
            ],
        )
    )
    assert await repo.reap_stale(3600, now=NOW) == 1

    run = (await repo.list("t1", limit=10))[0]
    by_name = {s["name"]: s["status"] for s in run["stages"]}
    assert by_name["ingest"] == ScanStatus.SUCCESS.value  # already done → untouched
    assert by_name["probe"] == ScanStatus.FAILED.value  # was running → failed
    assert by_name["scan"] == ScanStatus.SKIPPED.value  # never started → skipped


async def test_find_active_full_detects_running_and_queued():
    mongo = FakeMongo()
    repo = ScanRunRepo.from_mongo(mongo)
    await repo.save(
        ScanRun(tenant_id="t1", scan_id="r", program_id="running", pipeline="full",
                status=ScanStatus.RUNNING, started_at=NOW)
    )
    await repo.save(
        ScanRun(tenant_id="t1", scan_id="q", program_id="queued", pipeline="full",
                status=ScanStatus.QUEUED)
    )
    await repo.save(
        ScanRun(tenant_id="t1", scan_id="d", program_id="done", pipeline="full",
                status=ScanStatus.SUCCESS, started_at=NOW)
    )
    assert await repo.find_active_full("t1", "running", now=NOW, stale_seconds=3600) is not None
    assert await repo.find_active_full("t1", "queued", now=NOW, stale_seconds=3600) is not None
    assert await repo.find_active_full("t1", "done", now=NOW, stale_seconds=3600) is None
    assert await repo.find_active_full("t1", "never", now=NOW, stale_seconds=3600) is None


async def test_find_active_full_excludes_stale_running():
    mongo = FakeMongo()
    repo = ScanRunRepo.from_mongo(mongo)
    await repo.save(
        ScanRun(tenant_id="t1", scan_id="old", program_id="p1", pipeline="full",
                status=ScanStatus.RUNNING, started_at=NOW - timedelta(hours=2))
    )
    # 2h old with a 1h staleness window → not blocking (reaper will close it)
    assert await repo.find_active_full("t1", "p1", now=NOW, stale_seconds=3600) is None


async def test_reaper_is_idempotent():
    mongo = FakeMongo()
    repo = ScanRunRepo.from_mongo(mongo)
    await _save(
        mongo, scan_id="stale", status=ScanStatus.RUNNING, started_at=NOW - timedelta(hours=2)
    )

    assert await repo.reap_stale(3600, now=NOW) == 1
    # second sweep finds nothing still RUNNING
    assert await repo.reap_stale(3600, now=NOW) == 0


async def test_reaper_spans_tenants():
    mongo = FakeMongo()
    repo = ScanRunRepo.from_mongo(mongo)
    await _save(
        mongo,
        scan_id="a",
        status=ScanStatus.RUNNING,
        started_at=NOW - timedelta(hours=2),
        tenant="t1",
    )
    await _save(
        mongo,
        scan_id="b",
        status=ScanStatus.RUNNING,
        started_at=NOW - timedelta(hours=2),
        tenant="t2",
    )
    assert await repo.reap_stale(3600, now=NOW) == 2


async def test_scheduler_tick_reaps_before_planning():
    mongo = FakeMongo()
    await ProgramRepo.from_mongo(mongo).save(
        Program(tenant_id="t1", program_id="p1", apex_domain="customer.com", verified=True)
    )
    await AuthorizationRepo.from_mongo(mongo).save(
        Authorization(tenant_id="t1", program_id="p1", authorized_by="u", apex_verified=True)
    )
    await _save(
        mongo, scan_id="stale", status=ScanStatus.RUNNING, started_at=NOW - timedelta(hours=2)
    )

    class _Enq:
        def __init__(self) -> None:
            self.jobs: list = []

        async def __call__(self, job) -> None:
            self.jobs.append(job)

    await Scheduler(mongo, _Enq()).run_once(NOW)

    run = await ScanRunRepo.from_mongo(mongo).list("t1", limit=100)
    stale = next(r for r in run if r["scan_id"] == "stale")
    assert stale["status"] == ScanStatus.FAILED.value and stale["error"] == "orphaned"
