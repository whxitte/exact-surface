"""Persistent license runtime state — the clock high-water-mark + any refreshed token.

A single document. The high-water-mark (`clock_floor`) is the latest wall-clock time the
instance has ever observed; it only moves forward. The clock-rollback guard in
``core.license.evaluate`` compares the current clock against it, so setting the system
clock back to dodge an expiry is detected (and forces read-only).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

_DOC_ID = "license"


class LicenseStateRepo:
    def __init__(self, collection: Any) -> None:
        self._c = collection

    @classmethod
    def from_mongo(cls, mongo: Any) -> LicenseStateRepo:
        return cls(mongo.collection("license_state"))

    async def get(self) -> dict | None:
        return await self._c.find_one({"_id": _DOC_ID})

    async def clock_floor(self) -> datetime | None:
        doc = await self.get()
        val = (doc or {}).get("clock_floor")
        if isinstance(val, datetime):
            return val if val.tzinfo else val.replace(tzinfo=UTC)
        return None

    async def bump_clock(self, now: datetime) -> datetime:
        """Move the high-water-mark forward to ``now`` (never backward). Returns the
        effective floor after the update."""
        current = await self.clock_floor()
        floor = now if current is None else max(current, now)
        await self._c.update_one(
            {"_id": _DOC_ID},
            {"$set": {"clock_floor": floor, "updated_at": now}},
            upsert=True,
        )
        return floor

    async def stored_token(self) -> str | None:
        """A license token delivered by the online refresh, if any (overrides the env/
        file token once fetched, so a renewal takes effect without a redeploy)."""
        return (await self.get() or {}).get("token")

    async def save_token(self, token: str) -> None:
        await self._c.update_one(
            {"_id": _DOC_ID},
            {"$set": {"token": token, "token_updated_at": datetime.now(UTC)}},
            upsert=True,
        )
