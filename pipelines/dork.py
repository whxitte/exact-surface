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


async def run_dork(
    *,
    mongo: Any,
    tenant: TenantContext,
    program_id: str,
    domain: str,
    search=None,
) -> dict:
    # Default search = Google CSE (tenant key first, then env); skip if unconfigured.
    if search is None:
        from db.integrations import resolve_secret
        from modules.dorking.google import search as google_search

        key = await resolve_secret(mongo, tenant.tenant_id, "google_cse_key")
        cx = await resolve_secret(mongo, tenant.tenant_id, "google_cse_cx")
        if not key or not cx:
            logger.info("dork {}: skipped (no search API key configured)", domain)
            return {
                "hits": 0,
                "new": 0,
                "skipped": True,
                "note": "needs a Google CSE API key — add one in Settings",
            }

        async def search(query: str) -> list[dict]:  # noqa: A001 - shadow is intentional
            return await google_search(query, key=key, cx=cx)

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
