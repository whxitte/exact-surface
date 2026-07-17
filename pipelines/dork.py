"""Dorking pipeline (module 18-20) — indexed exposures → findings.

Runs the dork templates against a search engine and records hits as Findings
(module ``dork``), with severity by category. The search callable is injected;
by default it degrades to no results unless a search API is configured.
"""

from __future__ import annotations

from typing import Any

from core.hashing import finding_fingerprint
from core.logging import logger
from core.models import Finding
from core.tenant import TenantContext
from db.findings import FindingRepo
from modules.dorking.templates import category_severity, render


async def _resolve_engine(mongo: Any, tenant_id: str):
    """Pick the first configured search engine, returning ``(search, name)``.

    Order is deliberate: Google CSE (a free tier exists), then Brave (cheap), then
    SerpAPI last because it is metered per search (§13 budgeting). Tenant-stored
    keys win over env defaults — see ``db.integrations.resolve_secret``.
    Returns ``(None, "")`` when nothing is configured, so the stage can skip
    honestly rather than report a misleading "0 hits".
    """
    from db.integrations import resolve_secret

    key = await resolve_secret(mongo, tenant_id, "google_cse_key")
    cx = await resolve_secret(mongo, tenant_id, "google_cse_cx")
    if key and cx:
        from modules.dorking.google import search as google_search

        async def google(query: str) -> list[dict]:
            return await google_search(query, key=key, cx=cx)

        return google, "google_cse"

    brave_key = await resolve_secret(mongo, tenant_id, "brave_api_key")
    if brave_key:
        from modules.dorking.brave import search as brave_search

        async def brave(query: str) -> list[dict]:
            return await brave_search(query, key=brave_key)

        return brave, "brave"

    serp_key = await resolve_secret(mongo, tenant_id, "serpapi_key")
    if serp_key:
        from modules.dorking.serpapi import search as serp_search

        async def serpapi(query: str) -> list[dict]:
            return await serp_search(query, key=serp_key)

        return serpapi, "serpapi"

    return None, ""


async def run_dork(
    *,
    mongo: Any,
    tenant: TenantContext,
    program_id: str,
    domain: str,
    search=None,
) -> dict:
    engine = ""
    if search is None:
        search, engine = await _resolve_engine(mongo, tenant.tenant_id)
        if search is None:
            logger.info("dork {}: skipped (no search API key configured)", domain)
            return {
                "hits": 0,
                "new": 0,
                "skipped": True,
                "note": (
                    "needs a search API key — add a Google CSE, Brave, or SerpAPI key in Settings"
                ),
            }
        logger.info("dork {}: using {}", domain, engine)

    models: list[Finding] = []
    seen: set[str] = set()
    for dork in render(domain):
        for item in await search(dork["query"]):
            link = item.get("link")
            if not link or link in seen:
                continue
            seen.add(link)
            check_id = f"dork:{dork['category']}"
            models.append(
                Finding(
                    tenant_id=tenant.tenant_id,
                    program_id=program_id,
                    fingerprint=finding_fingerprint(program_id, check_id, link),
                    check_id=check_id,
                    module="dork",
                    location=link,
                    name=f"Indexed exposure ({dork['category']})",
                    description=item.get("title") or "",
                    severity=category_severity(dork["category"]),
                )
            )
    total, new = await FindingRepo.from_mongo(mongo).upsert_many(models)
    logger.info("dork {}: {} hits, {} new", domain, total, new)
    return {"hits": total, "new": new}
