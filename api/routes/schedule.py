"""Account-level (tenant) scan-cadence defaults + the configurable-pipeline catalog.

Per-program overrides live under /programs/{id}/schedule; these are the defaults a
program falls back to when it has no override of its own.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from api.deps import Principal, get_mongo_dep, get_principal
from db.tenants import TenantRepo
from taskqueue.cadence import DEFAULT_CADENCE_SECONDS, MIN_INTERVAL_SECONDS, sanitize_overrides
from taskqueue.timeouts import (
    DEFAULT_TIMEOUTS_SECONDS,
    MAX_TIMEOUT_SECONDS,
    MIN_TIMEOUT_SECONDS,
    sanitize_timeout_overrides,
)

router = APIRouter(prefix="/schedule", tags=["schedule"])

#: human labels for the configurable pipelines (UI copy).
_PIPELINE_LABELS = {
    "ingest": "Subdomain enumeration",
    "probe": "HTTP probe",
    "crawl": "Crawl",
    "content_discovery": "Content discovery",
    "port_scan": "Port scan",
    "scan": "Vulnerability scan (nuclei)",
    "secrets": "Secret scan",
    "github_osint": "GitHub OSINT",
    "cve_watch": "CVE/KEV watch",
    "notify": "Notifications",
}


def _catalog() -> list[dict]:
    items = [
        {
            "pipeline": p,
            "label": _PIPELINE_LABELS.get(p, p),
            "default_seconds": secs,
        }
        for p, secs in DEFAULT_CADENCE_SECONDS.items()
    ]
    items.sort(key=lambda i: i["default_seconds"])
    return items


@router.get("/defaults")
async def get_defaults(
    principal: Principal = Depends(get_principal), mongo: Any = Depends(get_mongo_dep)
) -> dict:
    tenant = await TenantRepo.from_mongo(mongo).get(principal.tenant_id)
    return {
        "cadence_overrides": sanitize_overrides((tenant or {}).get("cadence_overrides")),
        "pipelines": _catalog(),
        "min_interval_seconds": MIN_INTERVAL_SECONDS,
    }


@router.post("/defaults")
async def set_defaults(
    body: dict,
    principal: Principal = Depends(get_principal),
    mongo: Any = Depends(get_mongo_dep),
) -> dict:
    overrides = sanitize_overrides(body.get("overrides") if isinstance(body, dict) else None)
    await TenantRepo.from_mongo(mongo).set_cadence_overrides(principal.tenant_id, overrides)
    return {"cadence_overrides": overrides, "pipelines": _catalog()}


def _timeout_catalog() -> list[dict]:
    items = [
        {"stage": s, "label": _PIPELINE_LABELS.get(s, s), "default_seconds": secs}
        for s, secs in DEFAULT_TIMEOUTS_SECONDS.items()
    ]
    items.sort(key=lambda i: i["default_seconds"])
    return items


@router.get("/timeout-defaults")
async def get_timeout_defaults(
    principal: Principal = Depends(get_principal), mongo: Any = Depends(get_mongo_dep)
) -> dict:
    tenant = await TenantRepo.from_mongo(mongo).get(principal.tenant_id)
    return {
        "timeout_overrides": sanitize_timeout_overrides((tenant or {}).get("timeout_overrides")),
        "stages": _timeout_catalog(),
        "min_seconds": MIN_TIMEOUT_SECONDS,
        "max_seconds": MAX_TIMEOUT_SECONDS,
    }


@router.post("/timeout-defaults")
async def set_timeout_defaults(
    body: dict,
    principal: Principal = Depends(get_principal),
    mongo: Any = Depends(get_mongo_dep),
) -> dict:
    overrides = sanitize_timeout_overrides(
        body.get("overrides") if isinstance(body, dict) else None
    )
    await TenantRepo.from_mongo(mongo).set_timeout_overrides(principal.tenant_id, overrides)
    return {"timeout_overrides": overrides, "stages": _timeout_catalog()}
