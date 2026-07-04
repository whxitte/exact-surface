"""Aggregated dashboard stats for the calling tenant."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from api.deps import Principal, get_mongo_dep, get_principal
from db.assets import AssetRepo
from db.endpoints import EndpointRepo
from db.findings import FindingRepo
from db.programs import ProgramRepo
from db.secrets import SecretRepo

router = APIRouter(tags=["stats"])


@router.get("/stats")
async def stats(
    principal: Principal = Depends(get_principal), mongo: Any = Depends(get_mongo_dep)
) -> dict:
    tid = principal.tenant_id
    findings = await FindingRepo.from_mongo(mongo).list(tid, limit=100_000)

    by_severity: dict[str, int] = {}
    new_findings = 0
    for f in findings:
        sev = f.get("severity", "info")
        by_severity[sev] = by_severity.get(sev, 0) + 1
        if f.get("is_new"):
            new_findings += 1

    return {
        "programs": len(await ProgramRepo.from_mongo(mongo).list(tid)),
        "assets": await AssetRepo.from_mongo(mongo).count(tid),
        "endpoints": await EndpointRepo.from_mongo(mongo).count(tid),
        "secrets": await SecretRepo.from_mongo(mongo).count(tid),
        "findings": len(findings),
        "new_findings": new_findings,
        "findings_by_severity": by_severity,
    }
