"""API-key collection access. Stores SHA-256 hashes only (§9)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
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

    async def get(self, tenant_id: str, key_id: str) -> dict | None:
        return await self._c.find_one({"tenant_id": tenant_id, "key_id": key_id})

    async def revoke(self, tenant_id: str, key_id: str) -> bool:
        """Mark revoked rather than delete: the key stops working immediately, and
        audit events that name its key_id still resolve to something."""
        res = await self._c.update_one(
            {"tenant_id": tenant_id, "key_id": key_id, "revoked_at": None},
            {"$set": {"revoked_at": datetime.now(UTC)}},
        )
        return res.modified_count > 0

    async def touch(self, tenant_id: str, key_id: str, *, older_than_seconds: int = 300) -> None:
        """Record use, at most once per *older_than_seconds*, so "is this key still
        used?" is answerable without a write on every request."""
        now = datetime.now(UTC)
        cutoff = now - timedelta(seconds=older_than_seconds)
        await self._c.update_one(
            {
                "tenant_id": tenant_id,
                "key_id": key_id,
                "$or": [{"last_used_at": None}, {"last_used_at": {"$lt": cutoff}}],
            },
            {"$set": {"last_used_at": now}},
        )
