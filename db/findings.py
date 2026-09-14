"""Finding collection access (nuclei / secret / port / dork findings)."""

from __future__ import annotations

from db.base import Repository


class FindingRepo(Repository):
    COLLECTION = "findings"

    async def mark_false_positive(self, tenant_id: str, fingerprint: str, reason: str) -> bool:
        """A module re-checked this finding and found nothing behind it.

        Moves it to FALSE_POSITIVE — a suppressed state that never re-alerts — but only
        from states the lifecycle allows, so a person's CONFIRMED or ACCEPTED_RISK is
        never overridden by a scanner. Returns True if the state changed. The reason is
        kept on the record: "re-verified on <date>: page does not contain …" is what the
        user needs to see when they wonder where a critical went.
        """
        from datetime import UTC, datetime

        from core.lifecycle import FindingState, can_transition

        doc = await self.get(tenant_id, fingerprint)
        if not doc:
            return False
        try:
            current = FindingState(doc.get("state") or FindingState.NEW.value)
        except ValueError:
            return False
        if current == FindingState.FALSE_POSITIVE or not can_transition(
            current, FindingState.FALSE_POSITIVE
        ):
            return False
        now = datetime.now(UTC)
        await self._c.update_one(
            {"tenant_id": tenant_id, "fingerprint": fingerprint},
            {
                "$set": {
                    "state": FindingState.FALSE_POSITIVE.value,
                    "updated_at": now,
                    "raw.verified": False,
                    "raw.retired_reason": reason,
                    "raw.retired_at": now,
                }
            },
        )
        return True
