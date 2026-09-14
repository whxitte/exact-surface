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
from core.severity import Severity
from core.tenant import TenantContext
from db.findings import FindingRepo
from modules.dorking.templates import category_severity, render
from modules.dorking.verify import Verification, verify_hit


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


async def _default_fetch(url: str) -> str:  # pragma: no cover - real network
    """Fetch one hit for verification: same guards as every other target request."""
    import aiohttp

    from modules.safe_http import assert_url_allowed, guarded_session

    assert_url_allowed(url)
    async with guarded_session() as session:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=15), ssl=False) as resp:
            if resp.status != 200:
                return ""
            return (await resp.text(errors="ignore"))[:2_000_000]


async def run_dork(
    *,
    mongo: Any,
    tenant: TenantContext,
    program_id: str,
    domain: str,
    search=None,
    fetch=None,
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

    fetch = fetch or _default_fetch
    findings_repo = FindingRepo.from_mongo(mongo)
    dropped = 0
    unverified = 0
    retired = 0

    async def _verify(dork: dict, item: dict) -> tuple[dict, dict, Verification]:
        async with sem:
            return dork, item, await verify_hit(dork["query"], item["link"], fetch, site=domain)

    hits: list[tuple[dict, dict]] = []
    for dork, items in await asyncio.gather(*(_one(d) for d in dorks)):
        for item in items:
            link = item.get("link")
            if not link or link in seen:
                continue
            seen.add(link)
            hits.append((dork, item))

    # A search hit is a lead, not a finding. Search engines stem, drop punctuation and
    # match OR-groups loosely — `"password="` returns any page that says "password" —
    # so every hit is checked against the page it points at before it is rated.
    # Structural dorks (ext:/inurl:) are checked on the URL with no request; content
    # dorks fetch the page once, under the same guards and rate cap as everything
    # else. Verified → the category's severity. Not verified → dropped, and logged,
    # because "a public page mentions the word password" is not an exposure. Could
    # not be checked → kept at LOW and labelled, since a blocked or rate-limited page
    # must not be mistaken for a clean one.
    for dork, item, v in await asyncio.gather(*(_verify(d, i) for d, i in hits)):
        query, link = dork["query"], item["link"]
        title = item.get("title") or ""
        snippet = item.get("snippet") or ""
        check_id = f"dork:{dork['category']}"
        if v.verified is False:
            dropped += 1
            logger.info("dork: dropped unverified hit {} for {} — {}", link, query, v.evidence)
            # If an earlier run stored this hit as a finding, it has now been positively
            # re-checked. Say so on the record rather than waiting for gone-detection,
            # which (rightly) distrusts a run that reports nothing — and a clean dork
            # run reports nothing, so those findings would otherwise never age out.
            if await findings_repo.mark_false_positive(
                tenant.tenant_id,
                finding_fingerprint(program_id, check_id, link),
                f"re-verified by dork: {v.evidence}",
            ):
                retired += 1
            continue
        if v.verified is None:
            unverified += 1
            severity = Severity.LOW
            name = f"Indexed exposure ({dork['category']}) — unverified"
            reproduction = f"Search: {query}  (page could not be fetched to confirm: {v.evidence})"
        else:
            severity = category_severity(dork["category"])
            name = f"Indexed exposure ({dork['category']})"
            reproduction = (
                f"curl -sk '{link}' | grep -i -- '{v.matched}'"
                if v.matched and v.matched != link
                else f"curl -sk '{link}'"
            )
        # Full transparency: the exact dork, what the engine returned, and what the
        # page itself showed when we looked.
        desc_parts = [p for p in (title, snippet) if p]
        if v.evidence:
            desc_parts.append(f"Verified on page: {v.evidence[:300]}")
        models.append(
            Finding(
                tenant_id=tenant.tenant_id,
                program_id=program_id,
                fingerprint=finding_fingerprint(program_id, check_id, link),
                check_id=check_id,
                module="dork",
                location=link,
                locator=query,
                name=name,
                description=" — ".join(desc_parts) or f"Indexed by: {query}",
                severity=severity,
                reproduction=reproduction,
                raw={
                    "dork_query": query,
                    "category": dork["category"],
                    "engine": engine,
                    "title": title,
                    "snippet": snippet,
                    "link": link,
                    "verified": v.verified,
                    "evidence": v.evidence,
                    "matched": v.matched,
                },
            )
        )
    total, new = await findings_repo.upsert_many(models)
    logger.info(
        "dork {}: {} search hits → {} verified, {} unverifiable (kept LOW), {} dropped "
        "({} earlier findings retired as false positives); {} new",
        domain,
        len(hits),
        total - unverified,
        unverified,
        dropped,
        retired,
        new,
    )
    return {
        "hits": total,
        "new": new,
        "dropped_unverified": dropped,
        "unverifiable": unverified,
        "retired_false_positives": retired,
    }
