"""User collection access. Email is globally unique (login is pre-tenant)."""

from __future__ import annotations

from typing import Any

from core.models import User
from db.base import _to_bson


class UserRepo:
    def __init__(self, collection: Any) -> None:
        self._c = collection

    @classmethod
    def from_mongo(cls, mongo: Any) -> UserRepo:
        return cls(mongo.collection("users"))

    async def get_by_email(self, email: str) -> dict | None:
        return await self._c.find_one({"email": email.lower()})

    async def get(self, tenant_id: str, user_id: str) -> dict | None:
        return await self._c.find_one({"tenant_id": tenant_id, "user_id": user_id})

    async def create(self, user: User) -> dict:
        doc = _to_bson(user.model_dump(mode="python"))
        doc["email"] = doc["email"].lower()
        await self._c.update_one({"user_id": doc["user_id"]}, {"$set": doc}, upsert=True)
        return doc
