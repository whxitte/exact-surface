"""User collection access. Email is globally unique (login is pre-tenant)."""

from __future__ import annotations

from datetime import datetime
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

    async def get_by_id(self, user_id: str) -> dict | None:
        return await self._c.find_one({"user_id": user_id})

    async def create(self, user: User) -> dict:
        doc = _to_bson(user.model_dump(mode="python"))
        doc["email"] = doc["email"].lower()
        await self._c.update_one({"user_id": doc["user_id"]}, {"$set": doc}, upsert=True)
        return doc

    async def list(self, tenant_id: str) -> list[dict]:
        """All users in a tenant (for the members-management UI)."""
        return await self._c.find({"tenant_id": tenant_id}).to_list(None)

    async def set_groups(self, tenant_id: str, user_id: str, group_ids: list[str]) -> bool:
        res = await self._c.update_one(
            {"tenant_id": tenant_id, "user_id": user_id},
            {"$set": {"group_ids": group_ids}},
        )
        return bool(getattr(res, "modified", 0) or getattr(res, "modified_count", 0))

    async def delete(self, tenant_id: str, user_id: str) -> bool:
        res = await self._c.delete_one({"tenant_id": tenant_id, "user_id": user_id})
        return bool(getattr(res, "deleted", 0) or getattr(res, "deleted_count", 0))

    async def count_owners(self, tenant_id: str) -> int:
        return await self._c.count_documents({"tenant_id": tenant_id, "role": "owner"})

    async def set_verification(
        self, user_id: str, *, token: str, expires_at: datetime, sent_at: datetime
    ) -> None:
        """Issue (or re-issue) a verification token for a user."""
        await self._c.update_one(
            {"user_id": user_id},
            {
                "$set": {
                    "verification_token": token,
                    "verification_expires_at": expires_at,
                    "verification_sent_at": sent_at,
                }
            },
        )

    async def verify_by_token(self, token: str, *, now: datetime) -> dict | None:
        """Consume a token: mark the user verified and clear the token. Returns the
        user doc on success, or ``None`` if the token is unknown or expired (the
        token is one-time — a used token no longer matches)."""
        doc = await self._c.find_one({"verification_token": token})
        if not doc:
            return None
        exp = doc.get("verification_expires_at")
        if exp is not None and now > exp:
            return None
        await self._c.update_one(
            {"user_id": doc["user_id"]},
            {
                "$set": {
                    "email_verified": True,
                    "verification_token": None,
                    "verification_expires_at": None,
                }
            },
        )
        doc["email_verified"] = True
        return doc
