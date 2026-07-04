"""Asset-change history (append-only event log)."""

from __future__ import annotations

from typing import Any

from core.models import Delta
from db.base import _to_bson


class DeltaRepo:
    def __init__(self, collection: Any) -> None:
        self._c = collection

    @classmethod
    def from_mongo(cls, mongo: Any) -> DeltaRepo:
        return cls(mongo.collection("deltas"))

    async def record(self, delta: Delta) -> None:
        await self._c.insert_one(_to_bson(delta.model_dump(mode="python")))

    async def record_all(self, deltas: list[Delta]) -> int:
        for d in deltas:
            await self.record(d)
        return len(deltas)

    async def list(
        self, tenant_id: str, program_id: str | None = None, limit: int = 100
    ) -> list[dict]:
        flt: dict[str, Any] = {"tenant_id": tenant_id}
        if program_id is not None:
            flt["program_id"] = program_id
        return await self._c.find(flt).limit(limit).to_list(limit)
