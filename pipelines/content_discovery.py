"""Content-discovery pipeline (modules 15–17).

Runs feroxbuster against confirmed-dedicated hosts only (CONTENT_DISCOVERY is part
of the full action set, withheld from CDN/cloud-shared per §9b), choosing the
wordlist from each host's fingerprinted tech. Discovered paths are upserted as
Endpoints for the scan pipeline to pick up.
"""

from __future__ import annotations

from typing import Any

from core.hashing import endpoint_fingerprint
from core.logging import logger
from core.models import Endpoint
from core.scope import Action, ProgramScope, ScopeEngine
from core.tenant import TenantContext
from db.assets import AssetRepo
from db.endpoints import EndpointRepo
from modules.content_discovery.feroxbuster import discover as ferox_discover
from modules.content_discovery.wordlist_selector import select_wordlist


async def run_content_discovery(
    *,
    mongo: Any,
    engine: ScopeEngine,
    scope: ProgramScope,
    tenant: TenantContext,
    program_id: str,
    timeout: float,
    discover=ferox_discover,
    wordlist_for=select_wordlist,
) -> dict:
    tid = tenant.tenant_id
    assets = await AssetRepo.from_mongo(mongo).list(tid, program_id, limit=100_000)
    endpoints = await EndpointRepo.from_mongo(mongo).list(tid, program_id, limit=100_000)

    # tech per host, taken from the host's root endpoint if we probed one
    tech_by_host: dict[str, list[str]] = {}
    for ep in endpoints:
        from urllib.parse import urlsplit

        host = urlsplit(ep["url"]).hostname or ""
        if ep.get("tech") and host not in tech_by_host:
            tech_by_host[host] = ep["tech"]

    found_models: list[Endpoint] = []
    scanned = 0
    for asset in assets:
        host = asset["hostname"]
        if not engine.evaluate(host, asset.get("resolved_ips", []), scope).permits(
            Action.CONTENT_DISCOVERY
        ):
            continue
        scanned += 1
        logger.info("content-discovery on {} with feroxbuster", host)
        wordlist = wordlist_for(tech_by_host.get(host, []))
        for hit in await discover(f"https://{host}", wordlist, timeout):
            found_models.append(
                Endpoint(
                    tenant_id=tid,
                    program_id=program_id,
                    fingerprint=endpoint_fingerprint(program_id, "GET", hit["url"]),
                    url=hit["url"],
                    method="GET",
                    status_code=hit.get("status"),
                )
            )

    if scanned == 0:
        logger.info("content-discovery {}: no confirmed-dedicated hosts to scan", program_id)
        return {
            "hosts": 0, "paths": 0, "new": 0,
            "skipped": True,
            "note": "no confirmed-dedicated hosts — bruteforce withheld on shared infra (§9b)",
        }

    total, new = await EndpointRepo.from_mongo(mongo).upsert_many(found_models)
    logger.info("content-discovery {}: {} hosts, {} paths, {} new", program_id, scanned, total, new)
    return {"hosts": scanned, "paths": total, "new": new}
