"""Permission-group collection access (§ RBAC). Tenant-scoped."""

from __future__ import annotations

from typing import Any

from core.models import Group
from db.base import _to_bson


class GroupRepo:
    def __init__(self, collection: Any) -> None:
        self._c = collection

    @classmethod
    def from_mongo(cls, mongo: Any) -> GroupRepo:
        return cls(mongo.collection("groups"))

    async def get(self, tenant_id: str, group_id: str) -> dict | None:
        return await self._c.find_one({"tenant_id": tenant_id, "group_id": group_id})

    async def list(self, tenant_id: str) -> list[dict]:
        return await self._c.find({"tenant_id": tenant_id}).to_list(None)

    async def list_by_ids(self, tenant_id: str, group_ids: list[str]) -> list[dict]:
        if not group_ids:
            return []
        return await self._c.find({"tenant_id": tenant_id, "group_id": {"$in": group_ids}}).to_list(
            None
        )

    async def save(self, group: Group) -> dict:
        doc = _to_bson(group.model_dump(mode="python"))
        await self._c.update_one(
            {"tenant_id": doc["tenant_id"], "group_id": doc["group_id"]},
            {"$set": doc},
            upsert=True,
        )
        return doc

    async def delete(self, tenant_id: str, group_id: str) -> bool:
        res = await self._c.delete_one({"tenant_id": tenant_id, "group_id": group_id})
        return bool(getattr(res, "deleted", 0) or getattr(res, "deleted_count", 0))

    async def permissions_for_ids(self, tenant_id: str, group_ids: list[str]) -> set[str]:
        """Union of the permissions across the given groups (unknown ids ignored)."""
        perms: set[str] = set()
        for g in await self.list_by_ids(tenant_id, group_ids):
            perms.update(g.get("permissions") or [])
        return perms
