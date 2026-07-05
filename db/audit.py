"""Scan-run audit trail (§4 db/audit.py)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

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

    async def list(
        self, tenant_id: str, program_id: str | None = None, limit: int = 100
    ) -> list[dict]:
        flt: dict[str, Any] = {"tenant_id": tenant_id}
        if program_id is not None:
            flt["program_id"] = program_id
        return await self._c.find(flt).limit(limit).to_list(limit)

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
