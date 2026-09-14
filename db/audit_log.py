"""The action audit log: who did what, to which program, with what outcome.

Append-only. Nothing in the product edits or deletes an event; retention is a
scripts/retention.py concern like everything else. The collection is indexed on
(tenant_id, ts) because "what happened here recently" is the only query anyone runs.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from core.models import AuditEvent
from db.base import _to_bson


class AuditLogRepo:
    def __init__(self, collection: Any) -> None:
        self._c = collection

    @classmethod
    def from_mongo(cls, mongo: Any) -> AuditLogRepo:
        return cls(mongo.collection("audit_events"))

    async def record(self, event: AuditEvent) -> None:
        await self._c.insert_one(_to_bson(event.model_dump(mode="python")))

    async def list(
        self,
        tenant_id: str,
        *,
        limit: int = 100,
        before: datetime | None = None,
        program_id: str | None = None,
        actor_id: str | None = None,
    ) -> list[dict]:
        flt: dict[str, Any] = {"tenant_id": tenant_id}
        if before is not None:
            flt["ts"] = {"$lt": before}
        if program_id:
            flt["program_id"] = program_id
        if actor_id:
            flt["$or"] = [{"actor_id": actor_id}, {"key_id": actor_id}]
        limit = max(1, min(int(limit), 500))
        return await self._c.find(flt).sort("ts", -1).limit(limit).to_list(limit)
