"""Retention purge — delete discovered data past its configured retention window."""

from __future__ import annotations

import argparse
import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from core.logging import logger

#: collection -> the timestamp field that decides its age. `last_seen` where we have it,
#: because re-observation makes a record current again.
PURGEABLE: dict[str, str] = {
    "findings": "last_seen",
    "endpoints": "last_seen",
    "ports": "last_seen",
    "secrets": "last_seen",
    "leaks": "last_seen",
    "cve_matches": "last_seen",
    "js_files": "last_seen",
    "deltas": "created_at",
    "scan_runs": "started_at",
}

#: Never touched, whatever the tier. See the module docstring.
PROTECTED: frozenset[str] = frozenset(
    {
        "assets",
        "programs",
        "authorizations",
        "tenants",
        "users",
        "groups",
        "api_keys",
        "integrations",
        "notifications",
        "schedule",
        "domain_intel",
        "scope_feed",
    }
)

#: Floor on any retention window. Even the cheapest tier keeps a month, so a
#: misconfigured or corrupt plan value can never wipe a customer's data.
MIN_RETENTION_DAYS = 30


@dataclass
class PurgeResult:
    tenant_id: str
    retention_days: int
    cutoff: datetime
    deleted: dict[str, int] = field(default_factory=dict)

    @property
    def total(self) -> int:
        return sum(self.deleted.values())


def cutoff_for(retention_days: int, now: datetime) -> datetime:
    """The timestamp before which records are expired, with the floor applied."""
    return now - timedelta(days=max(int(retention_days), MIN_RETENTION_DAYS))


async def purge_tenant(
    mongo: Any,
    tenant_id: str,
    retention_days: int,
    *,
    now: datetime | None = None,
    dry_run: bool = False,
) -> PurgeResult:
    """Delete this tenant's expired records. Tenant-scoped on every query, so a purge
    can never reach across tenants even if called with a wrong id."""
    now = now or datetime.now(UTC)
    cutoff = cutoff_for(retention_days, now)
    result = PurgeResult(tenant_id=tenant_id, retention_days=retention_days, cutoff=cutoff)

    for collection, field_name in PURGEABLE.items():
        if collection in PROTECTED:  # belt and braces; the two lists must not overlap
            continue
        query = {"tenant_id": tenant_id, field_name: {"$lt": cutoff}}
        try:
            if dry_run:
                count = await mongo.collection(collection).count_documents(query)
            else:
                outcome = await mongo.collection(collection).delete_many(query)
                count = getattr(outcome, "deleted_count", 0) or 0
        except Exception as exc:  # noqa: BLE001 - one collection must not stop the rest
            logger.warning("retention: {} purge failed for {}: {}", collection, tenant_id, exc)
            continue
        if count:
            result.deleted[collection] = count

    if result.total:
        logger.info(
            "retention: {} — {} record(s) older than {} ({} day window){}",
            tenant_id,
            result.total,
            cutoff.date(),
            result.retention_days,
            " [dry run]" if dry_run else "",
        )
    return result


async def purge_all(
    mongo: Any, *, now: datetime | None = None, dry_run: bool = False
) -> list[PurgeResult]:
    """Purge every tenant at its retention window."""
    from db.programs import tenant_limits

    tenants = await mongo.collection("tenants").find({}).to_list(None)
    results: list[PurgeResult] = []
    for tenant in tenants:
        tid = tenant.get("tenant_id")
        if not tid:
            continue
        limits = await tenant_limits(mongo, tid)
        results.append(
            await purge_tenant(mongo, tid, limits.retention_days, now=now, dry_run=dry_run)
        )
    return results


async def _main(dry_run: bool) -> int:  # pragma: no cover - CLI
    from db.mongo import get_mongo

    results = await purge_all(get_mongo(), dry_run=dry_run)
    total = sum(r.total for r in results)
    print(
        f"retention: {total} record(s) across {len(results)} tenant(s)"
        + (" would be deleted [dry run]" if dry_run else " deleted")
    )
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI
    ap = argparse.ArgumentParser(description="Purge data past its plan's retention window")
    ap.add_argument("--dry-run", action="store_true", help="count without deleting")
    raise SystemExit(asyncio.run(_main(ap.parse_args().dry_run)))
