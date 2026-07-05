"""Crawl pipeline — deepen endpoint discovery (modules 9, 10).

Combines passive archive sources (gau + waybackurls on the apex) with active
crawling (katana on scope-permitted hosts). All discovered URLs are filtered to
in-scope hosts and upserted as Endpoints for later probing/scanning. Output is
capped so an archive with tens of thousands of URLs cannot blow up a run.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from core.hashing import endpoint_fingerprint
from core.logging import logger
from core.models import Endpoint
from core.scope import Action, ProgramScope, ScopeEngine
from core.tenant import TenantContext
from db.assets import AssetRepo
from db.endpoints import EndpointRepo
from modules.crawling.gau import fetch_urls as gau_fetch
from modules.crawling.katana import crawl as katana_crawl
from modules.crawling.waybackurls import fetch_urls as wayback_fetch

MAX_ENDPOINTS_PER_RUN = 2000


async def run_crawl(
    *,
    mongo: Any,
    engine: ScopeEngine,
    scope: ProgramScope,
    tenant: TenantContext,
    program_id: str,
    apex: str,
    timeout: float,
    gau=gau_fetch,
    wayback=wayback_fetch,
    katana=katana_crawl,
) -> dict:
    urls: set[str] = set()

    # Passive archive sources (allowed for any in-scope program).
    for source in (gau, wayback):
        try:
            urls.update(await source(apex, timeout))
        except Exception as exc:  # noqa: BLE001 - archive sources are flaky; degrade
            logger.warning("crawl archive source failed for {}: {}", apex, exc)

    # Active crawl of hosts whose scope permits HTTP probing.
    assets = await AssetRepo.from_mongo(mongo).list(tenant.tenant_id, program_id, limit=100_000)
    for asset in assets:
        decision = engine.evaluate(asset["hostname"], asset.get("resolved_ips", []), scope)
        if not decision.permits(Action.HTTP_PROBE):
            continue
        try:
            urls.update(await katana(f"https://{asset['hostname']}", timeout))
        except Exception as exc:  # noqa: BLE001
            logger.warning("katana crawl failed for {}: {}", asset["hostname"], exc)

    # Keep only in-scope hosts, cap volume.
    in_scope_urls = [u for u in sorted(urls) if scope.owns_host(urlsplit(u).hostname or "")][
        :MAX_ENDPOINTS_PER_RUN
    ]

    models = [
        Endpoint(
            tenant_id=tenant.tenant_id,
            program_id=program_id,
            fingerprint=endpoint_fingerprint(program_id, "GET", u),
            url=u,
            method="GET",
        )
        for u in in_scope_urls
    ]
    if not assets and not in_scope_urls:
        logger.info("crawl {}: nothing to crawl yet (no assets, no archive urls)", apex)
        return {
            "discovered_urls": 0, "in_scope": 0, "endpoints": 0, "new": 0,
            "skipped": True, "note": "no assets discovered yet — run discovery first",
        }

    total, new = await EndpointRepo.from_mongo(mongo).upsert_many(models)

    logger.info("crawl {}: {} urls in-scope, {} new endpoints", apex, len(in_scope_urls), new)
    return {
        "discovered_urls": len(urls),
        "in_scope": len(in_scope_urls),
        "endpoints": total,
        "new": new,
    }
