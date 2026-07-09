"""Crawl pipeline — deepen endpoint discovery (modules 9, 10).

Combines passive archive sources (gau + waybackurls on the apex) with active
crawling (katana on scope-permitted hosts). All discovered URLs are filtered to
in-scope hosts and upserted as Endpoints for later probing/scanning. Output is
capped so an archive with tens of thousands of URLs cannot blow up a run.
"""

from __future__ import annotations

import asyncio
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
#: active-crawl bounds so one run cannot blow the job's time budget. katana at
#: depth 2 over dozens of hosts, each at the full tool timeout, was the cause of
#: full-run timeouts; cap the host count and give each host a small slice.
MAX_ACTIVE_CRAWL_HOSTS = 25
MAX_HOST_CRAWL_SECONDS = 45.0
# gau --subs harvests the whole domain's archived URLs and can be slow on a big
# domain; give it real time and run it alongside waybackurls (not after) so the
# passive phase is max(gau, wayback), not their sum.
MAX_PASSIVE_SECONDS = 300.0


async def run_crawl(
    *,
    mongo: Any,
    engine: ScopeEngine,
    scope: ProgramScope,
    tenant: TenantContext,
    program_id: str,
    apex: str,
    timeout: float,
    targets: set[str] | None = None,
    gau=gau_fetch,
    wayback=wayback_fetch,
    katana=katana_crawl,
) -> dict:
    urls: set[str] = set()
    passive_timeout = min(timeout, MAX_PASSIVE_SECONDS)
    host_timeout = min(timeout, MAX_HOST_CRAWL_SECONDS)

    # Passive archive is apex-wide, so it's only worthwhile for the periodic full
    # crawl. A targeted cascade run focuses on the specific new hosts (active katana
    # only) — the apex archive was already harvested on the last full crawl.
    if not targets:
        logger.info("crawl: harvesting archives for {} (gau + waybackurls)", apex)
        for name, result in zip(
            ("gau", "waybackurls"),
            await asyncio.gather(
                gau(apex, passive_timeout),
                wayback(apex, passive_timeout),
                return_exceptions=True,
            ),
            strict=True,
        ):
            if isinstance(result, BaseException):
                logger.warning("crawl archive source {} failed for {}: {}", name, apex, result)
            else:
                urls.update(result)
                logger.info("crawl: {} returned {} archived url(s)", name, len(result))

    # Active crawl of hosts whose scope permits HTTP probing — capped so a domain
    # with dozens of subdomains cannot exceed the run's time budget.
    assets = await AssetRepo.from_mongo(mongo).list(tenant.tenant_id, program_id, limit=100_000)
    assets = [a for a in assets if a.get("monitored", True)]  # skip user-muted assets
    if targets:  # cascade: crawl only the newly discovered hosts
        assets = [a for a in assets if a["hostname"] in targets]
    crawl_hosts = [
        asset["hostname"]
        for asset in assets
        if engine.evaluate(asset["hostname"], asset.get("resolved_ips", []), scope).permits(
            Action.HTTP_PROBE
        )
    ][:MAX_ACTIVE_CRAWL_HOSTS]
    logger.info(
        "crawling archives (gau/wayback) on {} + active katana on {} host(s)",
        apex,
        len(crawl_hosts),
    )
    for hostname in crawl_hosts:
        logger.info("katana crawling {}", hostname)
        try:
            urls.update(await katana(f"https://{hostname}", host_timeout))
        except Exception as exc:  # noqa: BLE001
            logger.warning("katana crawl failed for {}: {}", hostname, exc)

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
            "discovered_urls": 0,
            "in_scope": 0,
            "endpoints": 0,
            "new": 0,
            "skipped": True,
            "note": "no assets discovered yet — run discovery first",
        }

    results = await EndpointRepo.from_mongo(mongo).upsert_all(models)
    new_urls = [m.url for m, r in zip(models, results, strict=True) if r.inserted]
    total, new = len(results), len(new_urls)
    # cascade: hosts that gained new endpoints → scan + secret-scan them next
    cascade_targets = sorted({urlsplit(u).hostname or "" for u in new_urls} - {""})

    logger.info("crawl {}: {} urls in-scope, {} new endpoints", apex, len(in_scope_urls), new)
    return {
        "discovered_urls": len(urls),
        "in_scope": len(in_scope_urls),
        "endpoints": total,
        "new": new,
        "cascade_targets": cascade_targets,
    }
