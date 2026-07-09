"""Scheduler cadence: due computation, fairness, auth-gating, idempotent ticks."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from core.models import Authorization, Program
from db.authorizations import AuthorizationRepo
from db.programs import ProgramRepo
from taskqueue.cadence import DEFAULT_CADENCE_SECONDS, is_due
from taskqueue.jobs import Priority
from taskqueue.scheduler import FULL_PIPELINE, Scheduler
from tests.fakes import FakeMongo

NOW = datetime(2026, 7, 4, 12, 0, 0, tzinfo=UTC)


class FakeEnqueuer:
    def __init__(self) -> None:
        self.jobs = []

    async def __call__(self, job) -> None:
        self.jobs.append(job)


async def _seed_ready(mongo, tenant="t1", pid="p1", apex="customer.com", *, bootstrapped=True):
    # `bootstrapped` = the initial full run already completed → per-phase cadence.
    # Set it in the past so nothing is spuriously "just scanned".
    await ProgramRepo.from_mongo(mongo).save(
        Program(
            tenant_id=tenant,
            program_id=pid,
            apex_domain=apex,
            verified=True,
            initial_scan_completed_at=(NOW - timedelta(days=30)) if bootstrapped else None,
        )
    )
    await AuthorizationRepo.from_mongo(mongo).save(
        Authorization(tenant_id=tenant, program_id=pid, authorized_by="u", apex_verified=True)
    )


# -- cadence -----------------------------------------------------------------
def test_is_due():
    assert is_due(None, NOW, 60) is True
    assert is_due(NOW - timedelta(seconds=10), NOW, 60) is False
    assert is_due(NOW - timedelta(seconds=120), NOW, 60) is True


# -- plan --------------------------------------------------------------------
async def test_plan_only_ready_programs():
    mongo = FakeMongo()
    await _seed_ready(mongo, pid="ready")
    # unverified program
    await ProgramRepo.from_mongo(mongo).save(
        Program(tenant_id="t1", program_id="unverified", apex_domain="x.com", verified=False)
    )
    # verified but no authorization
    await ProgramRepo.from_mongo(mongo).save(
        Program(tenant_id="t1", program_id="noauth", apex_domain="y.com", verified=True)
    )

    jobs = await Scheduler(mongo, FakeEnqueuer()).plan(NOW)
    assert {j.program_id for j in jobs} == {"ready"}
    # every cadence pipeline is due first-run, at NEW_ASSET priority
    assert {j.pipeline for j in jobs} == set(DEFAULT_CADENCE_SECONDS)
    assert all(j.priority == Priority.NEW_ASSET for j in jobs)


async def test_plan_fairness_cap():
    mongo = FakeMongo()
    await _seed_ready(mongo)
    jobs = await Scheduler(mongo, FakeEnqueuer(), max_per_tenant=3).plan(NOW)
    assert len(jobs) == 3  # capped regardless of how many pipelines are due


# -- run_once ----------------------------------------------------------------
async def test_run_once_enqueues_then_is_idempotent_within_interval():
    mongo = FakeMongo()
    await _seed_ready(mongo)
    enq = FakeEnqueuer()
    sched = Scheduler(mongo, enq)

    first = await sched.run_once(NOW)
    assert first == len(DEFAULT_CADENCE_SECONDS) and len(enq.jobs) == first

    # same tick time → nothing is due again
    second = await sched.run_once(NOW)
    assert second == 0

    # far in the future → everything is due again
    later = await sched.run_once(NOW + timedelta(days=2))
    assert later == len(DEFAULT_CADENCE_SECONDS)


async def test_cve_watch_recurs_faster_than_ingest():
    mongo = FakeMongo()
    await _seed_ready(mongo)
    sched = Scheduler(mongo, FakeEnqueuer())
    await sched.run_once(NOW)

    # 20 minutes later: cve_watch (15m) is due again, ingest (6h) is not
    jobs = await sched.plan(NOW + timedelta(minutes=20))
    due = {j.pipeline for j in jobs}
    assert "cve_watch" in due and "ingest" not in due


# -- bootstrap: first-run full pipeline, then per-phase cadence ---------------
async def test_new_program_bootstraps_one_full_run_not_per_phase():
    mongo = FakeMongo()
    await _seed_ready(mongo, bootstrapped=False)  # never completed a full run
    jobs = await Scheduler(mongo, FakeEnqueuer()).plan(NOW)
    assert len(jobs) == 1
    assert jobs[0].pipeline == FULL_PIPELINE
    assert jobs[0].priority == Priority.NEW_ASSET and jobs[0].reason == "initial-full"


async def test_bootstrap_not_re_enqueued_while_full_run_active():
    from core.models import ScanRun, ScanStatus
    from db.audit import ScanRunRepo

    mongo = FakeMongo()
    await _seed_ready(mongo, bootstrapped=False)
    # a full run is already in flight → scheduler must not enqueue another
    await ScanRunRepo.from_mongo(mongo).save(
        ScanRun(
            tenant_id="t1",
            scan_id="s",
            program_id="p1",
            pipeline="full",
            status=ScanStatus.RUNNING,
            started_at=NOW,
        )
    )
    jobs = await Scheduler(mongo, FakeEnqueuer()).plan(NOW)
    assert jobs == []


async def test_program_switches_to_per_phase_after_initial_scan():
    mongo = FakeMongo()
    await _seed_ready(mongo, bootstrapped=True)
    jobs = await Scheduler(mongo, FakeEnqueuer()).plan(NOW)
    assert FULL_PIPELINE not in {j.pipeline for j in jobs}
    assert {j.pipeline for j in jobs} == set(DEFAULT_CADENCE_SECONDS)


async def test_per_program_cadence_override_changes_due_set():
    mongo = FakeMongo()
    await _seed_ready(mongo, bootstrapped=True)
    # slow ingest right down for this program; run once so nothing is first-run-due
    await ProgramRepo.from_mongo(mongo).set_cadence_overrides(
        "t1", "p1", {"ingest": 30 * 24 * 3600}
    )
    sched = Scheduler(mongo, FakeEnqueuer())
    await sched.run_once(NOW)
    # 8h later: default ingest (6h) would be due, but the 30-day override is not
    jobs = await sched.plan(NOW + timedelta(hours=8))
    assert "ingest" not in {j.pipeline for j in jobs}
