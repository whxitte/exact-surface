"""Dorking pipeline (module 18-20) — indexed exposures → findings.

Runs the dork templates against a search engine and records hits as Findings
(module ``dork``), with severity by category. The search callable is injected;
by default it degrades to no results unless a search API is configured.
"""

from __future__ import annotations

import asyncio
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


#: Queries in flight at once. Search APIs rate-limit aggressively, so this is small on
#: purpose — enough to fit the stage budget, not enough to get throttled.
DORK_CONCURRENCY = 4
#: Per-query ceiling. A single slow query is dropped rather than starving the rest.
DORK_QUERY_TIMEOUT = 20.0


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

    dorks = render(domain)
    logger.info(
        "dork {}: running {} search quer(ies) via {}", domain, len(dorks), engine or "injected"
    )

    # Run a few at a time rather than strictly sequentially. 29 queries at up to 20s
    # each is ~10 minutes, which blew the stage budget and failed the whole stage with
    # "timed out" — losing the results it had already collected. Bounded concurrency
    # keeps us inside budget while staying gentle on the search API's rate limit.
    sem = asyncio.Semaphore(DORK_CONCURRENCY)

    async def _one(dork: dict) -> tuple[dict, list[dict]]:
        query = dork["query"]
        async with sem:
            try:
                items = await asyncio.wait_for(search(query), timeout=DORK_QUERY_TIMEOUT)
            except (TimeoutError, Exception) as exc:  # noqa: BLE001
                # One dead query must not cost us the other 28 — the search APIs are
                # flaky and rate-limited, and partial dork results are still useful.
                logger.info("dork: query timed out or failed ({}): {}", type(exc).__name__, query)
                return dork, []
        logger.info("dork: {} → {} result(s)", query, len(items))
        return dork, items

    for dork, items in await asyncio.gather(*(_one(d) for d in dorks)):
        query = dork["query"]
        for item in items:
            link = item.get("link")
            if not link or link in seen:
                continue
            seen.add(link)
            check_id = f"dork:{dork['category']}"
            title = item.get("title") or ""
            snippet = item.get("snippet") or ""
            # Full transparency: the finding carries the EXACT dork query that
            # matched, the search-result title + snippet (the indexed content the
            # engine returned), and a reproduction the user can paste into Google.
            # Nothing about why this was flagged is hidden.
            desc_parts = [p for p in (title, snippet) if p]
            models.append(
                Finding(
                    tenant_id=tenant.tenant_id,
                    program_id=program_id,
                    fingerprint=finding_fingerprint(program_id, check_id, link),
                    check_id=check_id,
                    module="dork",
                    location=link,
                    locator=query,  # the exact dork that surfaced this
                    name=f"Indexed exposure ({dork['category']})",
                    description=" — ".join(desc_parts) or f"Indexed by: {query}",
                    severity=category_severity(dork["category"]),
                    reproduction=f"Search Google for: {query}",
                    raw={
                        "dork_query": query,
                        "category": dork["category"],
                        "engine": engine,
                        "title": title,
                        "snippet": snippet,
                        "link": link,
                    },
                )
            )
    total, new = await FindingRepo.from_mongo(mongo).upsert_many(models)
    logger.info("dork {}: {} hits, {} new", domain, total, new)
    return {"hits": total, "new": new}
