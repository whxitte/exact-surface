"""Tenant collection access."""

from __future__ import annotations

from typing import Any

from core.models import Tenant
from db.base import _to_bson


class TenantRepo:
    def __init__(self, collection: Any) -> None:
        self._c = collection

    @classmethod
    def from_mongo(cls, mongo: Any) -> TenantRepo:
        return cls(mongo.collection("tenants"))

    async def get(self, tenant_id: str) -> dict | None:
        return await self._c.find_one({"tenant_id": tenant_id})

    async def create(self, tenant: Tenant) -> dict:
        doc = _to_bson(tenant.model_dump(mode="python"))
        await self._c.update_one({"tenant_id": doc["tenant_id"]}, {"$set": doc}, upsert=True)
        return doc

    async def set_cadence_overrides(self, tenant_id: str, overrides: dict[str, int]) -> None:
        await self._c.update_one(
            {"tenant_id": tenant_id}, {"$set": {"cadence_overrides": overrides}}
        )

    async def set_timeout_overrides(self, tenant_id: str, overrides: dict[str, int]) -> None:
        await self._c.update_one(
            {"tenant_id": tenant_id}, {"$set": {"timeout_overrides": overrides}}
        )

    async def set_alert_policy(self, tenant_id: str, policy: dict) -> None:
        await self._c.update_one({"tenant_id": tenant_id}, {"$set": {"alert_policy": policy}})
