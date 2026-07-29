"""Scan-run audit trail (§4 db/audit.py)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from core.activity_bus import publish_run
from core.logging import logger
from core.models import ScanRun, ScanStatus
from db.base import _to_bson


def _as_aware(dt: Any) -> datetime | None:
    """Coerce a stored timestamp to a tz-aware UTC datetime, or None if unusable."""
    if not isinstance(dt, datetime):
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


class ScanRunRepo:
    def __init__(self, collection: Any) -> None:
        self._c = collection

    @classmethod
    def from_mongo(cls, mongo: Any) -> ScanRunRepo:
        return cls(mongo.collection("scan_runs"))

    async def save(self, run: ScanRun) -> None:
        doc = _to_bson(run.model_dump(mode="python"))
        await self._c.update_one(
            {"tenant_id": doc["tenant_id"], "scan_id": doc["scan_id"]},
            {"$set": doc},
            upsert=True,
        )
        # Push the update so the /activity websocket reflects it live (no-op if no
        # bus configured — the frontend still polls).
        await publish_run(doc["tenant_id"], doc)

    async def get(self, tenant_id: str, scan_id: str) -> dict | None:
        return await self._c.find_one({"tenant_id": tenant_id, "scan_id": scan_id})

    async def request_cancel(
        self, tenant_id: str, scan_id: str, *, actor: str | None = None
    ) -> bool:
        """Ask a running scan to stop. Cooperative by design: this only sets a flag —
        the worker polls it between stages and on each heartbeat, then unwinds
        gracefully (killing in-flight tools, keeping everything already discovered).

        Only an in-flight run can be cancelled; a finished one is left alone so a late
        click can't rewrite history. Returns True if the request was recorded.
        """
        res = await self._c.update_one(
            {
                "tenant_id": tenant_id,
                "scan_id": scan_id,
                "status": {"$in": [ScanStatus.QUEUED.value, ScanStatus.RUNNING.value]},
            },
            {
                "$set": {
                    "cancel_requested": True,
                    "cancelled_at": datetime.now(UTC),
                    "cancelled_by": actor,
                    "updated_at": datetime.now(UTC),
                }
            },
        )
        return bool(getattr(res, "modified", 0) or getattr(res, "modified_count", 0))

    async def recent_cancelled_full(
        self, tenant_id: str, program_id: str, *, within_seconds: float, now: datetime | None = None
    ) -> dict | None:
        """The most recent user-cancelled full run, if it was cancelled recently.

        The scheduler consults this so a scan the user just stopped is not immediately
        re-enqueued by the bootstrap/cadence logic. Pressing stop must mean stopped.
        """
        now = now or datetime.now(UTC)
        cutoff = now - timedelta(seconds=within_seconds)
        rows = (
            await self._c.find(
                {
                    "tenant_id": tenant_id,
                    "program_id": program_id,
                    "pipeline": "full",
                    "status": ScanStatus.CANCELLED.value,
                }
            ).to_list(None)
        )
        for doc in rows:
            finished = _as_aware(doc.get("finished_at") or doc.get("cancelled_at"))
            if finished and finished >= cutoff:
                return doc
        return None

    async def is_cancel_requested(self, tenant_id: str, scan_id: str) -> bool:
        """Read the stop flag straight from the DB (never a cached copy) — the API and
        the worker are different processes, so this is the handoff."""
        doc = await self._c.find_one({"tenant_id": tenant_id, "scan_id": scan_id})
        return bool((doc or {}).get("cancel_requested"))

    async def list(
        self, tenant_id: str, program_id: str | None = None, limit: int = 100
    ) -> list[dict]:
        flt: dict[str, Any] = {"tenant_id": tenant_id}
        if program_id is not None:
            flt["program_id"] = program_id
        return await self._c.find(flt).limit(limit).to_list(limit)

    async def latest_full(self, tenant_id: str, program_id: str) -> dict | None:
        """The most recently started full run for a program (any status), for the
        'last scan' display. Reads the small per-program set and picks the newest."""
        docs = await self._c.find(
            {"tenant_id": tenant_id, "program_id": program_id, "pipeline": "full"}
        ).to_list(None)
        if not docs:
            return None
        return max(
            docs,
            key=lambda d: (
                _as_aware(d.get("started_at"))
                or _as_aware(d.get("created_at"))
                or datetime.min.replace(tzinfo=UTC)
            ),
        )

    async def find_active_full(
        self,
        tenant_id: str,
        program_id: str,
        *,
        now: datetime | None = None,
        stale_seconds: float | None = None,
    ) -> dict | None:
        """Return an in-flight (queued or running) full run for the program, else None.

        Used to refuse a duplicate scan while one is already active (backend-enforced,
        not just a frontend disable). A run older than ``stale_seconds`` is treated as
        NOT active — it is orphaned and the reaper will close it out, so a fresh scan
        is allowed rather than blocked forever by a dead run.
        """
        now = now or datetime.now(UTC)
        docs = await self._c.find(
            {
                "tenant_id": tenant_id,
                "program_id": program_id,
                "pipeline": "full",
                "status": {"$in": [ScanStatus.QUEUED.value, ScanStatus.RUNNING.value]},
            }
        ).to_list(None)
        for doc in docs:
            if stale_seconds is not None:
                ref = _as_aware(doc.get("started_at")) or _as_aware(doc.get("created_at"))
                if ref is not None and (now - ref).total_seconds() >= stale_seconds:
                    continue
            return doc
        return None

    async def active_phase_run(
        self,
        tenant_id: str,
        program_id: str,
        pipeline: str,
        *,
        fresh_seconds: float,
        now: datetime | None = None,
    ) -> dict | None:
        """A genuinely-alive whole-program run of *pipeline* (RUNNING + heartbeated within
        ``fresh_seconds``), else None. Used to avoid piling up concurrent runs of an
        expensive phase: a slow nuclei scan + a queue retry + the next cadence tick would
        otherwise stack several scans. Cascade (target-scoped) runs are ignored — they are
        small and cover just a new host — so only a whole-program run blocks another."""
        now = now or datetime.now(UTC)
        docs = await self._c.find(
            {
                "tenant_id": tenant_id,
                "program_id": program_id,
                "pipeline": pipeline,
                "status": ScanStatus.RUNNING.value,
            }
        ).to_list(None)
        for doc in docs:
            if doc.get("targets"):  # cascade — doesn't count as the whole-program run
                continue
            ref = _as_aware(doc.get("updated_at")) or _as_aware(doc.get("started_at"))
            if ref is not None and (now - ref).total_seconds() < fresh_seconds:
                return doc  # alive and heartbeating → a real duplicate
        return None

    async def reap_stale(self, older_than_seconds: float, now: datetime | None = None) -> int:
        """Mark orphaned QUEUED/RUNNING runs as FAILED("orphaned"); return count reaped.

        A worker killed or restarted mid-run leaves its ScanRun stuck ``RUNNING``
        forever (§ context.md known bug). This system-wide sweep — run each
        scheduler tick, so the first tick after startup also cleans up — closes out
        any run whose ``started_at`` is older than ``older_than_seconds`` so the
        activity feed reflects reality. Age is filtered in Python (the RUNNING set is
        tiny) to stay portable across the real driver and the test fake. If a worker
        is in fact still alive, its final ``save`` re-overwrites this FAILED record.
        """
        now = now or datetime.now(UTC)
        cutoff = now - timedelta(seconds=older_than_seconds)
        # RUNNING = worker died mid-run; QUEUED = enqueued but never picked up
        # (e.g. Redis/worker outage). Both go stale and must be closed out.
        active = await self._c.find(
            {"status": {"$in": [ScanStatus.RUNNING.value, ScanStatus.QUEUED.value]}}
        ).to_list(None)
        reaped = 0
        for doc in active:
            started = _as_aware(doc.get("started_at")) or _as_aware(doc.get("created_at"))
            if started is None or started >= cutoff:
                continue
            # Keep the per-stage stepper consistent: the stage that was mid-flight
            # failed with the run; stages that never started are skipped.
            stages = doc.get("stages") or []
            for st in stages:
                if st.get("status") == ScanStatus.RUNNING.value:
                    st["status"] = ScanStatus.FAILED.value
                    st["finished_at"] = now
                elif st.get("status") == ScanStatus.QUEUED.value:
                    st["status"] = ScanStatus.SKIPPED.value
            await self._c.update_one(
                {"tenant_id": doc["tenant_id"], "scan_id": doc["scan_id"]},
                {
                    "$set": {
                        "status": ScanStatus.FAILED.value,
                        "finished_at": now,
                        "error": "orphaned",
                        "stages": stages,
                    }
                },
            )
            reaped += 1
        if reaped:
            logger.warning("reaped {} orphaned (queued/running) scan-run(s)", reaped)
        return reaped
