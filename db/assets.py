"""Asset collection access + is_new bookkeeping."""

from __future__ import annotations

from db.base import Repository


class AssetRepo(Repository):
    COLLECTION = "assets"
    #: Fields written OUT-OF-BAND (via set_flag), not by the discovering upsert, so they
    #: must survive later re-upserts of the same asset:
    #:   * `monitored` — a user toggle.
    #:   * `takeover_risk` — set by the takeover stage; without preserving it, the very
    #:     next asset upsert (crawl/scan, which run after takeover) rewrites it to the
    #:     model default None, so the DNS page always showed "Takeover risks 0". The
    #:     takeover stage still self-clears it (set_flag → None) on a clean re-check.
    #:   * `interest` / `interest_reasons` — set by the probe stage from
    #:     classify_interest; like takeover_risk they must survive a later
    #:     crawl/scan asset upsert instead of resetting to the model default.
    PRESERVE_FIELDS = frozenset({"monitored", "takeover_risk", "interest", "interest_reasons"})

    async def set_monitored(self, tenant_id: str, fingerprint: str, monitored: bool) -> bool:
        return await self.set_flag(tenant_id, fingerprint, "monitored", monitored)

    async def set_interest(
        self, tenant_id: str, fingerprint: str, level: str, reasons: list[str]
    ) -> bool:
        """Set the interest level + reasons in one write (both are PRESERVE_FIELDS)."""
        from datetime import UTC, datetime

        res = await self._c.update_one(
            {"tenant_id": tenant_id, "fingerprint": fingerprint},
            {
                "$set": {
                    "interest": level,
                    "interest_reasons": reasons,
                    "updated_at": datetime.now(UTC),
                }
            },
        )
        return bool(getattr(res, "modified", 0) or getattr(res, "modified_count", 0))
