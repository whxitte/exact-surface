"""HTTP endpoint collection access."""

from __future__ import annotations

from datetime import UTC, datetime

from db.base import Repository


class EndpointRepo(Repository):
    COLLECTION = "endpoints"
    #: 403-bypass results are user-triggered, out-of-band data — not something the
    #: discovering module (probe/crawl) knows about. Keeping them in PRESERVE_FIELDS
    #: means a later re-scan's ``$set`` never wipes them; they're written via
    #: :meth:`record_bypass` instead.
    PRESERVE_FIELDS = frozenset({"bypass_attempted", "bypass_checked_at", "bypasses"})

    async def record_bypass(
        self,
        tenant_id: str,
        fingerprint: str,
        *,
        bypasses: list[dict],
        checked_at: datetime | None = None,
    ) -> bool:
        """Attach 403-bypass results to one endpoint (out-of-band of the upsert path).

        Returns True if it matched an endpoint. ``bypasses`` is the (possibly empty)
        list of successful bypasses; an empty list still records that we tried."""
        res = await self._c.update_one(
            {"tenant_id": tenant_id, "fingerprint": fingerprint},
            {
                "$set": {
                    "bypass_attempted": True,
                    "bypass_checked_at": checked_at or datetime.now(UTC),
                    "bypasses": bypasses,
                    "updated_at": datetime.now(UTC),
                }
            },
        )
        return bool(getattr(res, "modified", 0) or getattr(res, "modified_count", 0))
