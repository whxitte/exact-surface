"""Shared distribution of the CDN/cloud scope feed (§3.9, ADR-0014).

The feed (`core/data/cloud_ranges.json`) is what tells the engine an IP belongs to
Cloudflare/AWS/Akamai/… and therefore gets HTTP-layer probing only. It ships inside
the image, so updating it used to mean a rebuild — running `update_scope_feeds` on a
live host did nothing, because the running process never re-read the file.

Storing it in Mongo makes an update *distributable*: one job writes the shared copy,
and every process loads from it at startup. Mongo is the natural home — it is already
the single shared store every process connects to, so this needs no new volume
infrastructure and sidesteps k8s ReadWriteMany-volume pain.

**The bundled file is always the floor.** ``build_scope_engine`` uses the Mongo copy
only when it is present AND at least as protective as what ships in the image; a
missing, unreadable, or degraded Mongo feed falls back to the file. A scope feed that
loses ranges is a *removed protection* (§3.9), so the load path fails toward more
classification, never less — the same asymmetry the updater enforces on write.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from core.logging import logger
from core.scope import ScopeEngine

#: Single-document collection; the feed is global, not per-tenant.
_DOC_ID = "cloud_ranges"


def feed_cidr_count(feed: dict) -> int:
    return sum(len(p.get("cidrs", [])) for p in feed.get("providers", []))


class ScopeFeedRepo:
    def __init__(self, collection: Any) -> None:
        self._c = collection

    @classmethod
    def from_mongo(cls, mongo: Any) -> ScopeFeedRepo:
        return cls(mongo.collection("scope_feeds"))

    async def get(self) -> dict | None:
        """The stored feed dict, or None if none has been published yet."""
        doc = await self._c.find_one({"_id": _DOC_ID})
        if not doc:
            return None
        # Strip storage metadata; return the feed shape the engine expects.
        return {"_meta": doc.get("_meta", {}), "providers": doc.get("providers", [])}

    async def set(self, feed: dict, *, now: datetime | None = None) -> None:
        await self._c.update_one(
            {"_id": _DOC_ID},
            {
                "$set": {
                    "_meta": feed.get("_meta", {}),
                    "providers": feed.get("providers", []),
                    "cidr_count": feed_cidr_count(feed),
                    "updated_at": now or datetime.now(UTC),
                }
            },
            upsert=True,
        )


async def build_scope_engine(mongo: Any, *, allow_private: bool = False) -> ScopeEngine:
    """Build the scope engine, preferring the shared Mongo feed over the bundled file.

    Falls back to the bundled file when the Mongo copy is absent, unreadable, or
    smaller than what ships in the image. Losing feed ranges downgrades real CDN/
    cloud IPs to unclassified address space, so this deliberately never loads a feed
    that is *less* protective than the baseline — a corrupt or partial write cannot
    quietly widen scope.
    """
    baseline = ScopeEngine.bundled_feed()
    try:
        stored = await ScopeFeedRepo.from_mongo(mongo).get()
    except Exception as exc:  # noqa: BLE001 - a DB hiccup must not un-scope scanning
        logger.warning("scope feed: Mongo read failed ({}); using bundled file", exc)
        stored = None

    if stored is None:
        logger.info(
            "scope feed: no Mongo copy yet — using bundled file ({} cidrs)",
            feed_cidr_count(baseline),
        )
        return ScopeEngine.from_feed(baseline, allow_private=allow_private)

    stored_n, baseline_n = feed_cidr_count(stored), feed_cidr_count(baseline)
    if stored_n < baseline_n:
        # The updater only ever merges upward, so a Mongo copy below the bundled
        # baseline means corruption or a partial write — never trust it.
        logger.warning(
            "scope feed: Mongo copy has {} cidrs < bundled {} — using bundled file",
            stored_n,
            baseline_n,
        )
        return ScopeEngine.from_feed(baseline, allow_private=allow_private)

    logger.info("scope feed: loaded from Mongo ({} cidrs)", stored_n)
    return ScopeEngine.from_feed(stored, allow_private=allow_private)
