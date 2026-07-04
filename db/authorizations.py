"""Authorization-record collection access (§5d, §9b).

The pipeline refuses to run a program without a current authorization here.
"""

from __future__ import annotations

from typing import Any

from core.models import Authorization
from db.base import _to_bson


class AuthorizationRepo:
    def __init__(self, collection: Any) -> None:
        self._c = collection

    @classmethod
    def from_mongo(cls, mongo: Any) -> AuthorizationRepo:
        return cls(mongo.collection("authorizations"))

    async def get(self, tenant_id: str, program_id: str) -> dict | None:
        return await self._c.find_one({"tenant_id": tenant_id, "program_id": program_id})

    async def save(self, auth: Authorization) -> dict:
        doc = _to_bson(auth.model_dump(mode="python"))
        await self._c.update_one(
            {"tenant_id": doc["tenant_id"], "program_id": doc["program_id"]},
            {"$set": doc},
            upsert=True,
        )
        return doc
