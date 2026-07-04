"""Per-tenant notification channel config."""

from __future__ import annotations

from typing import Any

from core.models import NotificationChannel
from db.base import _to_bson


class NotificationChannelRepo:
    def __init__(self, collection: Any) -> None:
        self._c = collection

    @classmethod
    def from_mongo(cls, mongo: Any) -> NotificationChannelRepo:
        return cls(mongo.collection("notifications"))

    async def list(self, tenant_id: str, limit: int = 100) -> list[dict]:
        return await self._c.find({"tenant_id": tenant_id}).limit(limit).to_list(limit)

    async def get(self, tenant_id: str, channel_id: str) -> dict | None:
        return await self._c.find_one({"tenant_id": tenant_id, "channel_id": channel_id})

    async def save(self, channel: NotificationChannel) -> dict:
        doc = _to_bson(channel.model_dump(mode="python"))
        await self._c.update_one(
            {"tenant_id": doc["tenant_id"], "channel_id": doc["channel_id"]},
            {"$set": doc},
            upsert=True,
        )
        return doc

    async def delete(self, tenant_id: str, channel_id: str) -> None:
        await self._c.delete_one({"tenant_id": tenant_id, "channel_id": channel_id})
