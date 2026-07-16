"""Aggregated dashboard stats for the calling tenant."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from api.deps import Principal, clean_doc, get_mongo_dep, get_principal
from core.signal import summarize_findings
from db.assets import AssetRepo
from db.audit import ScanRunRepo
from db.endpoints import EndpointRepo
from db.findings import FindingRepo
from db.programs import ProgramRepo
from db.secrets import SecretRepo

router = APIRouter(tags=["stats"])


@router.get("/activity")
async def activity(
    principal: Principal = Depends(get_principal), mongo: Any = Depends(get_mongo_dep)
) -> list[dict]:
    """Recent scan-run activity for the tenant (most recent first) — powers the
    live workflow feed. Polled by the frontend; survives refresh (reads the DB)."""
    runs = await ScanRunRepo.from_mongo(mongo).list(principal.tenant_id, limit=200)
    runs.sort(key=lambda r: str(r.get("started_at") or r.get("created_at") or ""), reverse=True)
    return [clean_doc(r) for r in runs[:60]]


@router.get("/stats")
async def stats(
    principal: Principal = Depends(get_principal), mongo: Any = Depends(get_mongo_dep)
) -> dict:
    tid = principal.tenant_id
    findings = await FindingRepo.from_mongo(mongo).list(tid, limit=100_000)

    # Signal-quality rollup: actionable (open + medium↑) vs informational noise,
    # lifecycle breakdown, and the §15 false-positive rate.
    signal = summarize_findings(findings)

    return {
        "programs": len(await ProgramRepo.from_mongo(mongo).list(tid)),
        "assets": await AssetRepo.from_mongo(mongo).count(tid),
        "endpoints": await EndpointRepo.from_mongo(mongo).count(tid),
        "secrets": await SecretRepo.from_mongo(mongo).count(tid),
        # totals (kept for back-compat)
        "findings": signal["total"],
        "new_findings": signal["new"],
        "findings_by_severity": signal["by_severity"],
        # signal quality — what the dashboard should lead with
        "open_actionable": signal["open_actionable"],
        "informational": signal["informational"],
        "findings_by_state": signal["by_state"],
        "false_positive_rate": signal["false_positive_rate"],
        "false_positives": signal["false_positives"],
        "decided": signal["decided"],
    }
