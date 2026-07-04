"""State-aware enqueuer with per-tenant fairness (§4 taskqueue, ADR-0003).

The scheduler is the brain of the continuous engine. It never executes scans —
it reads DB state and decides what work is *worth* doing now, then enqueues jobs
that stateless workers pull. Decisions:

* only enabled + verified programs with a **current authorization** are scanned;
* each pipeline is due per its cadence + last-run state (unchanged assets are not
  re-scanned needlessly);
* a **never-run** (program, pipeline) is due immediately at higher priority
  (new-asset fast path);
* a **fairness cap** bounds jobs per tenant per tick so one big tenant cannot
  starve others.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

from core.config import Settings, get_settings
from core.logging import logger
from db.authorizations import AuthorizationRepo
from db.programs import ProgramRepo
from db.schedule import ScheduleRepo
from taskqueue.cadence import DEFAULT_CADENCE_SECONDS, is_due
from taskqueue.jobs import Job, Priority

Enqueuer = Callable[[Job], Awaitable[None]]


def _auth_current(auth: dict | None) -> bool:
    return bool(auth and auth.get("apex_verified") and not auth.get("revoked"))


class Scheduler:
    def __init__(
        self,
        mongo: Any,
        enqueuer: Enqueuer,
        *,
        settings: Settings | None = None,
        cadence: dict[str, int] | None = None,
        max_per_tenant: int | None = None,
    ) -> None:
        self._mongo = mongo
        self._enqueue = enqueuer
        self._settings = settings or get_settings()
        self._cadence = cadence or DEFAULT_CADENCE_SECONDS
        self._max_per_tenant = (
            max_per_tenant
            if max_per_tenant is not None
            else self._settings.scheduler_max_jobs_per_tenant
        )

    async def _ready_programs(self) -> list[dict]:
        """Programs eligible to scan: enabled, verified, and currently authorized."""
        ready: list[dict] = []
        auth_repo = AuthorizationRepo.from_mongo(self._mongo)
        for prog in await ProgramRepo.from_mongo(self._mongo).list_all():
            if not (prog.get("enabled", True) and prog.get("verified")):
                continue
            auth = await auth_repo.get(prog["tenant_id"], prog["program_id"])
            if _auth_current(auth):
                ready.append(prog)
        return ready

    async def plan(self, now: datetime | None = None) -> list[Job]:
        """Return the jobs that are due now, fairness-capped and priority-sorted."""
        now = now or datetime.now(UTC)
        schedule = ScheduleRepo.from_mongo(self._mongo)
        per_tenant: dict[str, int] = {}
        jobs: list[Job] = []

        for prog in await self._ready_programs():
            tid, pid = prog["tenant_id"], prog["program_id"]
            for pipeline, interval in self._cadence.items():
                last = await schedule.last_run(tid, pid, pipeline)
                if not is_due(last, now, interval):
                    continue
                if per_tenant.get(tid, 0) >= self._max_per_tenant:
                    continue
                jobs.append(
                    Job(
                        tenant_id=tid,
                        program_id=pid,
                        pipeline=pipeline,
                        priority=Priority.NEW_ASSET if last is None else Priority.NORMAL,
                        reason="cadence" if last else "first-run",
                    )
                )
                per_tenant[tid] = per_tenant.get(tid, 0) + 1

        jobs.sort(key=lambda j: j.priority)
        return jobs

    async def run_once(self, now: datetime | None = None) -> int:
        """Plan → enqueue → record last-run. Returns the number of jobs enqueued."""
        now = now or datetime.now(UTC)
        schedule = ScheduleRepo.from_mongo(self._mongo)
        jobs = await self.plan(now)
        for job in jobs:
            await self._enqueue(job)
            await schedule.mark_enqueued(job.tenant_id, job.program_id, job.pipeline, now)
        if jobs:
            logger.info("scheduler enqueued {} job(s)", len(jobs))
        return len(jobs)

    async def run_forever(self) -> None:  # pragma: no cover - infinite loop
        tick = self._settings.scheduler_tick_seconds
        logger.info("scheduler loop starting (tick={}s)", tick)
        while True:
            try:
                await self.run_once()
            except Exception as exc:  # noqa: BLE001 - a tick failure must not kill the loop
                logger.error("scheduler tick failed: {}", exc)
            await asyncio.sleep(tick)
