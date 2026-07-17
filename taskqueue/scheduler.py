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
from datetime import UTC, datetime, timedelta
from typing import Any

from core.config import Settings, get_settings
from core.logging import logger
from core.metrics import REGISTRY
from core.plans import allowed_program_ids
from db.audit import ScanRunRepo
from db.authorizations import AuthorizationRepo
from db.programs import ProgramRepo
from db.schedule import ScheduleRepo
from taskqueue.cadence import effective_cadence, is_due
from taskqueue.jobs import Job, Priority

Enqueuer = Callable[[Job], Awaitable[None]]

#: The bootstrap full run is enqueued under this pseudo-pipeline name; the arq
#: enqueuer routes it to ``run_program_task`` (the ordered 14-stage pipeline).
FULL_PIPELINE = "full"

#: If a bootstrap full job is enqueued but never lands (worker died, redis flushed),
#: re-arm it after this long. While queued arq dedups it; while running
#: ``find_active_full`` blocks a duplicate — so this only fires for genuinely lost jobs.
BOOTSTRAP_RETRY_SECONDS = 30 * 60


def _auth_current(auth: dict | None) -> bool:
    return bool(auth and auth.get("apex_verified") and not auth.get("revoked"))


def _observe_tick(status: str, *, jobs: int = 0, now: datetime | None = None) -> None:
    """Record the outcome of one scheduler tick.

    ``run_forever`` deliberately swallows tick exceptions so one bad tick cannot
    kill the loop — which means a scheduler failing *every* tick is externally
    indistinguishable from a healthy idle one. ``vantari_scheduler_last_success_
    timestamp`` is the fix: alert when ``time() - <gauge>`` exceeds a few ticks and
    you catch both a crashed loop and a silently-failing one.
    """
    REGISTRY.inc(
        "vantari_scheduler_ticks_total",
        help="Scheduler loop iterations by outcome.",
        status=status,
    )
    if status != "ok":
        return
    REGISTRY.set(
        "vantari_scheduler_last_success_timestamp",
        (now or datetime.now(UTC)).timestamp(),
        help="Unix time of the last scheduler tick that completed without error.",
    )
    if jobs:
        REGISTRY.inc(
            "vantari_scheduler_jobs_enqueued_total",
            value=float(jobs),
            help="Jobs enqueued by the scheduler.",
        )


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
        #: optional explicit cadence (tests); None → resolve per program from
        #: built-in defaults + tenant defaults + program overrides.
        self._cadence_override = cadence
        self._max_per_tenant = (
            max_per_tenant
            if max_per_tenant is not None
            else self._settings.scheduler_max_jobs_per_tenant
        )
        #: When the next scope-feed refresh is due. None → refresh on the first tick,
        #: so a fresh deployment publishes the merged feed to Mongo immediately.
        self._next_feed_refresh: datetime | None = None

    async def _tenant_defaults(self) -> dict[str, dict]:
        """tenant_id -> its account-level cadence overrides (empty if none)."""
        out: dict[str, dict] = {}
        for t in await self._mongo.collection("tenants").find({}).to_list(None):
            out[t["tenant_id"]] = t.get("cadence_overrides") or {}
        return out

    async def _plan_allowed(self, programs: list[dict]) -> set[str]:
        """Program ids inside each tenant's plan allowance (§13 — enforced at enqueue,
        so a downgrade takes effect on the next tick without deleting anything)."""
        by_tenant: dict[str, list[dict]] = {}
        for prog in programs:
            by_tenant.setdefault(prog["tenant_id"], []).append(prog)
        plans = {
            t["tenant_id"]: t.get("plan", "free")
            for t in await self._mongo.collection("tenants").find({}).to_list(None)
        }
        allowed: set[str] = set()
        for tid, progs in by_tenant.items():
            allowed |= allowed_program_ids(plans.get(tid, "free"), progs)
        return allowed

    async def _ready_programs(self) -> list[dict]:
        """Programs eligible to scan: enabled, verified, currently authorized, and
        inside the tenant's plan allowance."""
        all_programs = await ProgramRepo.from_mongo(self._mongo).list_all()
        allowed = await self._plan_allowed(all_programs)
        ready: list[dict] = []
        auth_repo = AuthorizationRepo.from_mongo(self._mongo)
        for prog in all_programs:
            if not (prog.get("enabled", True) and prog.get("verified")):
                continue
            if prog["program_id"] not in allowed:
                continue  # over plan quota — never enqueue work for it
            auth = await auth_repo.get(prog["tenant_id"], prog["program_id"])
            if _auth_current(auth):
                ready.append(prog)
        return ready

    async def plan(self, now: datetime | None = None) -> list[Job]:
        """Return the jobs that are due now, fairness-capped and priority-sorted.

        Two regimes per program:

        * **Bootstrap** — a program that has never completed a full run gets ONE
          ordered full-pipeline job (not a per-phase fan-out), so a new domain's
          first pass runs ingest→…→scan in order. Nothing else is enqueued for it
          until that completes.
        * **Steady state** — thereafter each phase recurs on its own effective
          cadence (built-in ← tenant defaults ← program overrides).
        """
        now = now or datetime.now(UTC)
        schedule = ScheduleRepo.from_mongo(self._mongo)
        audit = ScanRunRepo.from_mongo(self._mongo)
        tenant_defaults = await self._tenant_defaults()
        per_tenant: dict[str, int] = {}
        jobs: list[Job] = []

        def _capped(tid: str) -> bool:
            return per_tenant.get(tid, 0) >= self._max_per_tenant

        for prog in await self._ready_programs():
            tid, pid = prog["tenant_id"], prog["program_id"]

            # A full run covers every phase, so while one is in flight (e.g. a manual
            # re-scan) we must NOT also fan out per-phase cadence jobs — a second nuclei
            # then contends with the full run's scan and shows up as a stalled duplicate.
            active_full = await audit.find_active_full(
                tid, pid, now=now, stale_seconds=self._settings.scan_run_stale_seconds
            )
            if active_full is not None:
                continue

            # -- bootstrap: first full run before any per-phase cadence ----------
            if prog.get("initial_scan_completed_at") is None:
                if _capped(tid):
                    continue
                last_full = await schedule.last_run(tid, pid, FULL_PIPELINE)
                if is_due(last_full, now, BOOTSTRAP_RETRY_SECONDS):
                    jobs.append(
                        Job(
                            tenant_id=tid,
                            program_id=pid,
                            pipeline=FULL_PIPELINE,
                            priority=Priority.NEW_ASSET,
                            reason="initial-full",
                        )
                    )
                    per_tenant[tid] = per_tenant.get(tid, 0) + 1
                continue  # never fan out per-phase for an un-bootstrapped program

            # -- steady state: per-phase cadence --------------------------------
            cadence = self._cadence_override or effective_cadence(
                prog.get("cadence_overrides"), tenant_defaults.get(tid)
            )
            for pipeline, interval in cadence.items():
                last = await schedule.last_run(tid, pid, pipeline)
                if not is_due(last, now, interval):
                    continue
                if _capped(tid):
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
        try:
            await ScanRunRepo.from_mongo(self._mongo).reap_stale(
                self._settings.scan_run_stale_seconds, now=now
            )
        except Exception as exc:  # noqa: BLE001 - reaping must never block scheduling
            logger.error("scan-run reaper failed: {}", exc)
        schedule = ScheduleRepo.from_mongo(self._mongo)
        jobs = await self.plan(now)
        for job in jobs:
            await self._enqueue(job)
            await schedule.mark_enqueued(job.tenant_id, job.program_id, job.pipeline, now)
        if jobs:
            logger.info("scheduler enqueued {} job(s)", len(jobs))
        _observe_tick("ok", jobs=len(jobs), now=now)
        return len(jobs)

    async def maybe_refresh_scope_feed(self, now: datetime | None = None) -> bool:
        """Refresh the shared Mongo scope feed if it is due (ADR-0014). Returns True
        if a refresh ran. The scheduler is the natural owner: a singleton that is
        always up, so exactly one process fetches. Fully guarded — a feed refresh
        failing (network down, provider 500, a collapsed feed rejected) must never
        touch scan scheduling; the previous feed simply stays in place.
        """
        hours = self._settings.scope_feed_refresh_hours
        if hours <= 0:
            return False
        now = now or datetime.now(UTC)
        if self._next_feed_refresh is not None and now < self._next_feed_refresh:
            return False
        self._next_feed_refresh = now + timedelta(hours=hours)
        try:
            from scripts.update_scope_feeds import update_scope_feeds_to_mongo

            await update_scope_feeds_to_mongo(self._mongo)
            return True
        except Exception as exc:  # noqa: BLE001 - never let a feed refresh break scheduling
            logger.warning("scope feed refresh failed ({}); keeping the current feed", exc)
            return False

    async def run_forever(self) -> None:  # pragma: no cover - infinite loop
        tick = self._settings.scheduler_tick_seconds
        logger.info("scheduler loop starting (tick={}s)", tick)
        while True:
            try:
                await self.run_once()
                await self.maybe_refresh_scope_feed()
            except Exception as exc:  # noqa: BLE001 - a tick failure must not kill the loop
                logger.error("scheduler tick failed: {}", exc)
                _observe_tick("failed")
            await asyncio.sleep(tick)
