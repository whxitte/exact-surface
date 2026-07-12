"""Content-discovery pipeline (modules 15–17).

Runs feroxbuster against confirmed-dedicated hosts only (CONTENT_DISCOVERY is part
of the full action set, withheld from CDN/cloud-shared per §9b), choosing the
wordlist from each host's fingerprinted tech. Discovered paths are upserted as
Endpoints for the scan pipeline to pick up.
"""

from __future__ import annotations

import asyncio
from typing import Any
from urllib.parse import urlsplit

from core.errors import ToolNotFound
from core.hashing import endpoint_fingerprint
from core.logging import logger
from core.models import Endpoint
from core.scope import Action, ProgramScope, ScopeEngine
from core.tenant import TenantContext
from db.assets import AssetRepo
from db.endpoints import EndpointRepo
from modules.content_discovery.feroxbuster import TargetUnreachable
from modules.content_discovery.feroxbuster import discover as ferox_discover
from modules.content_discovery.wordlist_selector import select_wordlist

#: feroxbuster is slow per host (a big wordlist = minutes); run many hosts at once
#: and bound each so the stage stays well inside its budget.
CONCURRENCY = 10
PER_HOST_TIMEOUT = 120.0


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
    # Real content discovery needs wordlists installed; without them feroxbuster
    # silently finds nothing. Report that honestly (only when using the real tool).
    if discover is ferox_discover:
        from modules.content_discovery.wordlist_selector import wordlist_base, wordlists_installed

        if not wordlists_installed():
            logger.warning("content-discovery: no wordlists in {} — skipping", wordlist_base())
            return {
                "hosts": 0,
                "paths": 0,
                "new": 0,
                "skipped": True,
                "note": "content-discovery wordlists not installed",
            }

    assets = await AssetRepo.from_mongo(mongo).list(tid, program_id, limit=100_000)
    assets = [a for a in assets if a.get("monitored", True)]  # skip user-muted assets
    endpoints = await EndpointRepo.from_mongo(mongo).list(tid, program_id, limit=100_000)

    # tech per host, taken from the host's root endpoint if we probed one
    tech_by_host: dict[str, list[str]] = {}
    # The URL/scheme the host actually answered on during probe. feroxbuster does a
    # pre-flight connection and aborts the whole run with "Could not connect to any
    # target provided" if handed https:// for a host that only serves http — or has no
    # web server at all. So we only fuzz hosts we PROBED alive, at their working URL,
    # instead of blindly hitting https://<every dedicated host>.
    root_by_host: dict[str, str] = {}
    for ep in endpoints:
        host = urlsplit(ep["url"]).hostname or ""
        if ep.get("tech") and host not in tech_by_host:
            tech_by_host[host] = ep["tech"]
        parts = urlsplit(ep["url"])
        if not host or not parts.scheme:
            continue
        root = f"{parts.scheme}://{parts.netloc}"
        cur = root_by_host.get(host)
        # prefer https when a host answered on both schemes
        if cur is None or (root.startswith("https://") and not cur.startswith("https://")):
            root_by_host[host] = root

    scannable = [
        a["hostname"]
        for a in assets
        if a["hostname"] in root_by_host  # probed alive — has a working web root
        and engine.evaluate(a["hostname"], a.get("resolved_ips", []), scope).permits(
            Action.CONTENT_DISCOVERY
        )
    ]
    if not scannable:
        logger.info("content-discovery {}: no probed-alive dedicated hosts to scan", program_id)
        return {
            "hosts": 0,
            "paths": 0,
            "new": 0,
            "skipped": True,
            "note": "no probed-alive dedicated hosts (bruteforce withheld on shared infra §9b)",
        }

    per_host = min(timeout, PER_HOST_TIMEOUT)
    logger.info(
        "content-discovery: feroxbuster on {} host(s) (≤{:.0f}s each, {} at a time)",
        len(scannable),
        per_host,
        CONCURRENCY,
    )
    sem = asyncio.Semaphore(CONCURRENCY)

    async def _ffuf(target: str, wordlist: str, reason: str) -> list[dict]:
        # ffuf uses Go's HTTP stack (the same one httpx probed this host with), so it
        # connects where feroxbuster's client can't (IPv6/TLS quirks).
        try:
            from modules.content_discovery.ffuf import fuzz as ffuf_fuzz

            return await ffuf_fuzz(f"{target}/FUZZ", wordlist, per_host)
        except ToolNotFound:
            logger.warning("content-discovery: {} ({}), and ffuf not installed", target, reason)
            return []

    async def _scan_host(host: str) -> list[dict]:
        # Each host isolated + bounded: a slow/failing feroxbuster yields nothing for
        # that host but never sinks the (concurrent) stage.
        target = root_by_host[host]  # the scheme/host that answered during probe
        wordlist = wordlist_for(tech_by_host.get(host, []))
        async with sem:
            try:
                return await discover(target, wordlist, per_host)
            except ToolNotFound:  # feroxbuster missing entirely
                return await _ffuf(target, wordlist, "feroxbuster not installed")
            except TargetUnreachable as exc:  # feroxbuster's client couldn't connect
                logger.info("content-discovery: feroxbuster can't reach {} — trying ffuf", target)
                return await _ffuf(target, wordlist, str(exc))
            except Exception as exc:  # noqa: BLE001
                logger.warning("content-discovery: feroxbuster failed for {}: {}", host, exc)
                return []

    per_host_hits = await asyncio.gather(*(_scan_host(h) for h in scannable))

    found_models = [
        Endpoint(
            tenant_id=tid,
            program_id=program_id,
            fingerprint=endpoint_fingerprint(program_id, "GET", hit["url"]),
            url=hit["url"],
            method="GET",
            status_code=hit.get("status"),
            source="feroxbuster",
        )
        for hits in per_host_hits
        for hit in hits
    ]

    total, new = await EndpointRepo.from_mongo(mongo).upsert_many(found_models)
    logger.info(
        "content-discovery {}: {} hosts, {} paths, {} new", program_id, len(scannable), total, new
    )
    return {"hosts": len(scannable), "paths": total, "new": new}
