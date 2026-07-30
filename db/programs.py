"""Program collection access."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from core.models import Program
from core.plans import allowed_program_ids, can_add_domain
from db.base import _to_bson


class ProgramRepo:
    def __init__(self, collection: Any) -> None:
        self._c = collection

    @classmethod
    def from_mongo(cls, mongo: Any) -> ProgramRepo:
        return cls(mongo.collection("programs"))

    async def get(self, tenant_id: str, program_id: str) -> dict | None:
        return await self._c.find_one({"tenant_id": tenant_id, "program_id": program_id})

    async def list(self, tenant_id: str, limit: int = 1000) -> list[dict]:
        return await self._c.find({"tenant_id": tenant_id}).limit(limit).to_list(limit)

    async def list_all(self, limit: int = 100_000) -> list[dict]:
        """Every program across all tenants — for the system scheduler only."""
        return await self._c.find({}).limit(limit).to_list(limit)

    async def save(self, program: Program) -> dict:
        doc = _to_bson(program.model_dump(mode="python"))
        await self._c.update_one(
            {"tenant_id": doc["tenant_id"], "program_id": doc["program_id"]},
            {"$set": doc},
            upsert=True,
        )
        return doc

    async def _update(self, tenant_id: str, program_id: str, fields: dict) -> None:
        await self._c.update_one(
            {"tenant_id": tenant_id, "program_id": program_id}, {"$set": fields}
        )

    async def set_verification(self, tenant_id, program_id, method: str, token: str) -> None:
        await self._update(
            tenant_id, program_id, {"verification_method": method, "verification_token": token}
        )

    async def set_verified(self, tenant_id, program_id, verified: bool) -> None:
        await self._update(tenant_id, program_id, {"verified": verified})

    async def set_enabled(self, tenant_id, program_id, enabled: bool) -> None:
        await self._update(tenant_id, program_id, {"enabled": enabled})

    async def set_scan_shared_infra(self, tenant_id, program_id, value: bool) -> None:
        await self._update(tenant_id, program_id, {"scan_shared_infra": value})

    async def set_enabled_modules(self, tenant_id, program_id, modules: list[str]) -> None:
        await self._update(tenant_id, program_id, {"enabled_modules": modules})

    async def set_disabled_modules(self, tenant_id, program_id, modules: list[str]) -> None:
        await self._update(tenant_id, program_id, {"disabled_modules": modules})

    async def set_known_template_ids(self, tenant_id, program_id, ids: list[str]) -> None:
        """Record the nuclei templates relevant to this program (module 22 baseline)."""
        await self._update(tenant_id, program_id, {"known_template_ids": ids})

    async def set_cadence_overrides(self, tenant_id, program_id, overrides: dict[str, int]) -> None:
        await self._update(tenant_id, program_id, {"cadence_overrides": overrides})

    async def set_timeout_overrides(self, tenant_id, program_id, overrides: dict[str, int]) -> None:
        await self._update(tenant_id, program_id, {"timeout_overrides": overrides})

    async def set_alert_policy(self, tenant_id, program_id, policy: dict) -> None:
        await self._update(tenant_id, program_id, {"alert_policy": policy})

    async def mark_initial_scan_completed(self, tenant_id, program_id, when: datetime) -> None:
        """Record the first full-run completion timestamp (callers guard so it is
        only set once — it stays the *first* completion, not the latest)."""
        await self._update(tenant_id, program_id, {"initial_scan_completed_at": when})

    async def delete(self, tenant_id: str, program_id: str) -> None:
        await self._c.delete_one({"tenant_id": tenant_id, "program_id": program_id})


#: Collections that hold per-program data, purged when a program is deleted.
PROGRAM_DATA_COLLECTIONS: tuple[str, ...] = (
    "assets",
    "endpoints",
    "ports",
    "findings",
    "leaks",
    "deltas",
    "scan_runs",
    "authorizations",
)


async def delete_program_and_data(mongo: Any, tenant_id: str, program_id: str) -> None:
    """Hard-delete a program and every record scoped to it. Tenant-scoped so one
    tenant can never purge another's data."""
    flt = {"tenant_id": tenant_id, "program_id": program_id}
    for name in PROGRAM_DATA_COLLECTIONS:
        await mongo.collection(name).delete_many(flt)
    await ProgramRepo.from_mongo(mongo).delete(tenant_id, program_id)


# -- plan quota (§13) --------------------------------------------------------
# These cross tenants↔programs, so they live here rather than in pure ``core``.
async def tenant_plan(mongo: Any, tenant_id: str) -> Any:
    from db.tenants import TenantRepo

    tenant = await TenantRepo.from_mongo(mongo).get(tenant_id)
    return (tenant or {}).get("plan", "free")


async def tenant_can_add_domain(mongo: Any, tenant_id: str) -> bool:
    """True if the tenant's plan still has room for another program."""
    programs = await ProgramRepo.from_mongo(mongo).list(tenant_id)
    return can_add_domain(await tenant_plan(mongo, tenant_id), len(programs))


async def program_within_plan(mongo: Any, tenant_id: str, program_id: str) -> bool:
    """True if *program_id* is inside the tenant's plan allowance. The authoritative
    scan gate (§13 "checked at enqueue") — so a downgrade takes effect immediately
    without deleting anything."""
    programs = await ProgramRepo.from_mongo(mongo).list(tenant_id)
    return program_id in allowed_program_ids(await tenant_plan(mongo, tenant_id), programs)
