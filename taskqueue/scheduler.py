"""State-aware enqueuer with per-tenant fairness (§4 taskqueue, ADR-0003).

The scheduler is the brain of the continuous engine: it reads state and decides
what work is *worth* doing, rather than blindly re-scanning everything. It never
executes scans itself — it only enqueues :class:`~taskqueue.jobs.Job` objects that
stateless workers pull.

Cadence policy (built out in Phase B/D):
  * newly discovered assets  → probe + scan immediately (Priority.NEW_ASSET)
  * KEV/CVE match            → priority rescan (Priority.KEV_PRIORITY)
  * unchanged alive assets   → delta re-check every few hours, full rescan slower
  * fairness                 → round-robin across tenants so one big tenant cannot
                                starve others (see taskqueue.fairness)

Phase A ships the interface and a no-op planner; the cadence logic lands in Phase B.
"""

from __future__ import annotations

from collections.abc import Sequence

from core.config import Settings, get_settings
from core.logging import logger
from taskqueue.jobs import Job


class Scheduler:
    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()

    async def plan(self) -> Sequence[Job]:
        """Return the set of jobs that should run now, based on current DB state.

        Phase A: returns nothing (no state yet, no pipelines yet). Phase B fills in
        the cadence + fairness logic reading from ``db/``.
        """
        logger.debug("scheduler.plan() called; cadence logic is a Phase B deliverable")
        return ()

    async def enqueue(self, jobs: Sequence[Job]) -> int:
        """Push jobs onto the queue, collapsing duplicates by ``dedup_key``.

        Wired to arq/redis in Phase B.
        """
        unique: dict[str, Job] = {}
        for job in jobs:
            unique.setdefault(job.dedup_key(), job)
        logger.info("scheduler would enqueue {} unique job(s)", len(unique))
        return len(unique)
