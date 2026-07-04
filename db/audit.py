"""Scan-run audit trail (§4 db/audit.py)."""

from __future__ import annotations

from typing import Any

from core.models import ScanRun
from db.base import _to_bson


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
