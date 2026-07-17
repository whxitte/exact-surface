"""Plan quota is enforced at ENQUEUE, not just at the API (§13).

The spec is explicit: "plan limits are checked at enqueue (before a scan consumes
resources), and plan changes take effect immediately." So a downgrade must stop
the scheduler enqueueing work for the over-quota program on the very next tick,
and ``run_program`` must independently refuse — covering a job that was already
queued in Redis before the downgrade landed.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from core.models import Authorization, Program, Tenant, VerificationMethod
from core.scope import ScopeEngine
from core.tenant import TenantContext
from db.authorizations import AuthorizationRepo
from db.programs import ProgramRepo
from db.tenants import TenantRepo
from pipelines.orchestrate import run_program
from taskqueue.scheduler import Scheduler
from tests.fakes import FakeMongo

ENGINE = ScopeEngine.from_data_file()
TID = "t_plan"


def _run(coro):
    return asyncio.run(coro)


def _seed(fake, *, plan: str, count: int = 2):
    _run(TenantRepo.from_mongo(fake).create(Tenant(tenant_id=TID, name="P")))
    _run(fake.collection("tenants").update_one({"tenant_id": TID}, {"$set": {"plan": plan}}))
    pids = []
    for i in range(count):
        pid = f"prog_{i}"
        _run(
            ProgramRepo.from_mongo(fake).save(
                Program(
                    tenant_id=TID,
                    program_id=pid,
                    apex_domain=f"d{i}.com",
                    verified=True,
                    enabled=True,
                    created_at=datetime(2026, 1, i + 1, tzinfo=UTC),
                )
            )
        )
        _run(
            AuthorizationRepo.from_mongo(fake).save(
                Authorization(
                    tenant_id=TID,
                    program_id=pid,
                    authorized_by="u1",
                    verification_method=VerificationMethod.DNS_TXT,
                    apex_verified=True,
                )
            )
        )
        pids.append(pid)
    return pids


class _NoopEnqueuer:
    async def __call__(self, job) -> None:  # plan() never enqueues; kept inert
        return None


def _scheduled_program_ids(fake) -> set[str]:
    jobs = _run(Scheduler(fake, _NoopEnqueuer()).plan())
    return {j.program_id for j in jobs}


def test_scheduler_enqueues_only_within_plan_allowance():
    fake = FakeMongo()
    first, second = _seed(fake, plan="free")  # free = 1 domain
    scheduled = _scheduled_program_ids(fake)
    assert first in scheduled
    assert second not in scheduled, "over-quota program was enqueued — plan limit not enforced"


def test_upgrade_lets_the_scheduler_pick_up_the_second_program():
    fake = FakeMongo()
    first, second = _seed(fake, plan="free")
    assert _scheduled_program_ids(fake) == {first}
    # plan changes take effect immediately — next tick includes both
    _run(fake.collection("tenants").update_one({"tenant_id": TID}, {"$set": {"plan": "pro"}}))
    assert _scheduled_program_ids(fake) == {first, second}


def test_run_program_refuses_over_quota_job():
    """Defense in depth: a job queued before the downgrade must not scan."""
    fake = FakeMongo()
    _first, second = _seed(fake, plan="free")
    out = _run(
        run_program(
            mongo=fake,
            engine=ENGINE,
            tenant=TenantContext(tenant_id=TID),
            program_id=second,
            timeout=5,
            force=True,  # even an explicit user-triggered run is refused
        )
    )
    assert out.get("skipped") is True
    assert "plan" in out.get("note", "")
