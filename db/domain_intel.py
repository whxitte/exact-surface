"""Per-program domain intelligence: email posture + registration facts.

This is *state*, not a stream of events — "DMARC policy is none" and "expires in 214
days" describe how the domain stands right now, so they belong in a record the UI can
render as a panel. The matching Findings still exist for alerting and triage; this is
what the user looks at to understand their posture at a glance.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any


class DomainIntelRepo:
    def __init__(self, collection: Any) -> None:
        self._c = collection

    @classmethod
    def from_mongo(cls, mongo: Any) -> DomainIntelRepo:
        return cls(mongo.collection("domain_intel"))

    async def get(self, tenant_id: str, program_id: str) -> dict | None:
        return await self._c.find_one({"tenant_id": tenant_id, "program_id": program_id})

    async def save(
        self, tenant_id: str, program_id: str, *, email: dict, registration: dict
    ) -> None:
        """One document per program, overwritten each run — the latest assessment is
        the only one that matters, and the Findings carry the history."""
        await self._c.update_one(
            {"tenant_id": tenant_id, "program_id": program_id},
            {
                "$set": {
                    "tenant_id": tenant_id,
                    "program_id": program_id,
                    "email": email,
                    "registration": registration,
                    "checked_at": datetime.now(UTC),
                }
            },
            upsert=True,
        )
