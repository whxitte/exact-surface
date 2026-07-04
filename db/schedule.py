"""Per-(program, pipeline) last-run schedule state.

Backs the scheduler's due-computation. Keyed on ``(tenant_id, fingerprint)`` where
fingerprint is ``"{program_id}:{pipeline}"`` — reusing the standard unique key so a
program can track each pipeline's cadence independently.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any


def schedule_key(program_id: str, pipeline: str) -> str:
    return f"{program_id}:{pipeline}"


class ScheduleRepo:
    def __init__(self, collection: Any) -> None:
        self._c = collection

    @classmethod
    def from_mongo(cls, mongo: Any) -> ScheduleRepo:
        return cls(mongo.collection("schedule"))

    async def last_run(self, tenant_id: str, program_id: str, pipeline: str) -> datetime | None:
        doc = await self._c.find_one(
            {"tenant_id": tenant_id, "fingerprint": schedule_key(program_id, pipeline)}
        )
        return doc.get("last_run_at") if doc else None

    async def mark_enqueued(
        self, tenant_id: str, program_id: str, pipeline: str, when: datetime
    ) -> None:
        key = schedule_key(program_id, pipeline)
        await self._c.update_one(
            {"tenant_id": tenant_id, "fingerprint": key},
            {
                "$set": {
                    "tenant_id": tenant_id,
                    "program_id": program_id,
                    "pipeline": pipeline,
                    "fingerprint": key,
                    "last_run_at": when,
                }
            },
            upsert=True,
        )
