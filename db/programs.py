"""Program collection access."""

from __future__ import annotations

from typing import Any

from core.models import Program
from db.base import _to_bson


class ProgramRepo:
    def __init__(self, collection: Any) -> None:
        self._c = collection

    @classmethod
    def from_mongo(cls, mongo: Any) -> ProgramRepo:
        return cls(mongo.collection("programs"))

    async def get(self, tenant_id: str, program_id: str) -> dict | None:
        return await self._c.find_one({"tenant_id": tenant_id, "program_id": program_id})

    async def list(self, tenant_id: str, limit: int = 1000) -> list[dict]:
        return await self._c.find({"tenant_id": tenant_id}).limit(limit).to_list(limit)

    async def list_all(self, limit: int = 100_000) -> list[dict]:
        """Every program across all tenants — for the system scheduler only."""
        return await self._c.find({}).limit(limit).to_list(limit)

    async def save(self, program: Program) -> dict:
        doc = _to_bson(program.model_dump(mode="python"))
        await self._c.update_one(
            {"tenant_id": doc["tenant_id"], "program_id": doc["program_id"]},
            {"$set": doc},
            upsert=True,
        )
        return doc

    async def _update(self, tenant_id: str, program_id: str, fields: dict) -> None:
        await self._c.update_one(
            {"tenant_id": tenant_id, "program_id": program_id}, {"$set": fields}
        )

    async def set_verification(self, tenant_id, program_id, method: str, token: str) -> None:
        await self._update(
            tenant_id, program_id, {"verification_method": method, "verification_token": token}
        )

    async def set_verified(self, tenant_id, program_id, verified: bool) -> None:
        await self._update(tenant_id, program_id, {"verified": verified})

    async def set_enabled(self, tenant_id, program_id, enabled: bool) -> None:
        await self._update(tenant_id, program_id, {"enabled": enabled})

    async def set_scan_shared_infra(self, tenant_id, program_id, value: bool) -> None:
        await self._update(tenant_id, program_id, {"scan_shared_infra": value})
