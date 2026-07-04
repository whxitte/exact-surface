"""API-key collection access. Stores SHA-256 hashes only (§9)."""

from __future__ import annotations

from typing import Any

from core.models import ApiKey
from db.base import _to_bson


class ApiKeyRepo:
    def __init__(self, collection: Any) -> None:
        self._c = collection

    @classmethod
    def from_mongo(cls, mongo: Any) -> ApiKeyRepo:
        return cls(mongo.collection("apikeys"))

    async def get_by_hash(self, key_hash: str) -> dict | None:
        return await self._c.find_one({"key_hash": key_hash})

    async def create(self, key: ApiKey) -> dict:
        doc = _to_bson(key.model_dump(mode="python"))
        await self._c.update_one({"key_id": doc["key_id"]}, {"$set": doc}, upsert=True)
        return doc

    async def list(self, tenant_id: str, limit: int = 100) -> list[dict]:
        return await self._c.find({"tenant_id": tenant_id}).limit(limit).to_list(limit)
