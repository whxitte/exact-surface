"""Asset collection access + is_new bookkeeping."""

from __future__ import annotations

from db.base import Repository


class AssetRepo(Repository):
    COLLECTION = "assets"
    #: `monitored` is a user toggle, not scanner output — keep it across re-scans.
    PRESERVE_FIELDS = frozenset({"monitored"})

    async def set_monitored(self, tenant_id: str, fingerprint: str, monitored: bool) -> bool:
        return await self.set_flag(tenant_id, fingerprint, "monitored", monitored)
