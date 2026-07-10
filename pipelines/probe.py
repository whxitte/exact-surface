"""Probe pipeline — assets → alive HTTP endpoints (module 5).

Enforces scope per asset: only hosts whose scope decision permits HTTP_PROBE are
sent to httpx (CDN/cloud-shared included — HTTP probing is allowed there; port/
active scanning is not). Produces Endpoints with a content hash for later delta
detection.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from core.hashing import canonical_hash, endpoint_fingerprint
from core.logging import logger
from core.models import Endpoint
from core.scope import Action, ProgramScope, ScopeEngine
from core.tenant import TenantContext
from db.assets import AssetRepo
from db.deltas import DeltaRepo
from db.endpoints import EndpointRepo
from modules.intelligence.delta_monitor import compute_endpoint_deltas
from modules.probing.httpx import probe as httpx_probe


async def run_probe(
    *,
    mongo: Any,
    engine: ScopeEngine,
    scope: ProgramScope,
    tenant: TenantContext,
    program_id: str,
    timeout: float,
    targets: set[str] | None = None,
    probe=httpx_probe,
) -> dict:
    assets = await AssetRepo.from_mongo(mongo).list(tenant.tenant_id, program_id, limit=100_000)
    assets = [a for a in assets if a.get("monitored", True)]  # skip user-muted assets
    if targets:  # cascade: scope this run to the newly discovered hosts
        assets = [a for a in assets if a["hostname"] in targets]

    probeable: list[str] = []
    for asset in assets:
        decision = engine.evaluate(asset["hostname"], asset.get("resolved_ips", []), scope)
        if decision.permits(Action.HTTP_PROBE):
            probeable.append(asset["hostname"])

    if not probeable:
        logger.info("probe {}: nothing to probe (no assets yet)", program_id)
        return {
            "probeable": 0,
            "alive": 0,
            "new": 0,
            "new_urls": [],
            "deltas": 0,
            "skipped": True,
            "note": "no assets to probe yet — run discovery first",
        }

    logger.info(
        "probing {} of {} asset(s) with httpx (the rest didn't resolve or aren't HTTP-probeable)",
        len(probeable),
        len(assets),
    )
    results = await probe(probeable, timeout)
    models = [
        Endpoint(
            tenant_id=tenant.tenant_id,
            program_id=program_id,
            fingerprint=endpoint_fingerprint(program_id, "GET", r["url"]),
            url=r["url"],
            method="GET",
            status_code=r.get("status_code"),
            title=r.get("title"),
            tech=r.get("tech") or [],
            source="probe",
            # Content identity = title + tech only. Status is tracked separately so a
            # status change and a content change are independent delta signals.
            content_hash=canonical_hash(r.get("title"), sorted(r.get("tech") or [])),
        )
        for r in results
    ]
    endpoint_repo = EndpointRepo.from_mongo(mongo)
    delta_repo = DeltaRepo.from_mongo(mongo)

    # Detect state changes against the stored version BEFORE overwriting it.
    deltas = []
    for model in models:
        old = await endpoint_repo.get(tenant.tenant_id, model.fingerprint)
        deltas.extend(compute_endpoint_deltas(tenant.tenant_id, program_id, old, model))

    res = await endpoint_repo.upsert_all(models)
    await delta_repo.record_all(deltas)
    new_urls = [m.url for m, x in zip(models, res, strict=True) if x.inserted]
    # cascade: hosts that just came alive → crawl + port-scan them next
    cascade_targets = sorted({urlsplit(u).hostname or "" for u in new_urls} - {""})

    logger.info(
        "probe {}: {} probeable, {} alive, {} new, {} deltas",
        program_id,
        len(probeable),
        len(models),
        len(new_urls),
        len(deltas),
    )
    return {
        "probeable": len(probeable),
        "alive": len(models),
        "new": len(new_urls),
        "new_urls": new_urls,
        "deltas": len(deltas),
        "cascade_targets": cascade_targets,
    }
