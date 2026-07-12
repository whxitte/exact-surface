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
    PRESERVE_FIELDS = frozenset({"monitored", "takeover_risk"})

    async def set_monitored(self, tenant_id: str, fingerprint: str, monitored: bool) -> bool:
        return await self.set_flag(tenant_id, fingerprint, "monitored", monitored)
