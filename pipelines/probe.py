"""Probe pipeline — assets → alive HTTP endpoints (module 5).

Enforces scope per asset: only hosts whose scope decision permits HTTP_PROBE are
sent to httpx (CDN/cloud-shared included — HTTP probing is allowed there; port/
active scanning is not). Produces Endpoints with a content hash for later delta
detection.
"""

from __future__ import annotations

from typing import Any

from core.hashing import canonical_hash, endpoint_fingerprint
from core.logging import logger
from core.models import Endpoint
from core.scope import Action, ProgramScope, ScopeEngine
from core.tenant import TenantContext
from db.assets import AssetRepo
from db.endpoints import EndpointRepo
from modules.probing.httpx import probe as httpx_probe


async def run_probe(
    *,
    mongo: Any,
    engine: ScopeEngine,
    scope: ProgramScope,
    tenant: TenantContext,
    program_id: str,
    timeout: float,
    probe=httpx_probe,
) -> dict:
    assets = await AssetRepo.from_mongo(mongo).list(tenant.tenant_id, program_id, limit=100_000)

    probeable: list[str] = []
    for asset in assets:
        decision = engine.evaluate(asset["hostname"], asset.get("resolved_ips", []), scope)
        if decision.permits(Action.HTTP_PROBE):
            probeable.append(asset["hostname"])

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
            content_hash=canonical_hash(
                r.get("title"), r.get("status_code"), sorted(r.get("tech") or [])
            ),
        )
        for r in results
    ]
    res = await EndpointRepo.from_mongo(mongo).upsert_all(models)
    new_urls = [m.url for m, x in zip(models, res, strict=True) if x.inserted]

    logger.info(
        "probe {}: {} probeable, {} alive, {} new",
        program_id, len(probeable), len(models), len(new_urls),
    )
    return {
        "probeable": len(probeable),
        "alive": len(models),
        "new": len(new_urls),
        "new_urls": new_urls,
    }
