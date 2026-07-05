"""CVE-watch pipeline (module 21) — fingerprints → matched CVEs → priority alerts.

Reads the tenant's fingerprinted endpoints, matches their tech against the CVE/KEV
feed with confidence scoring, and upserts CveMatch records. Only genuinely new,
*alertable* (high-confidence / KEV) matches are returned for notification + a
priority rescan — low-confidence matches accumulate silently in the DB.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from core.cpe import parse_tech
from core.hashing import asset_fingerprint, cve_match_fingerprint
from core.logging import logger
from core.models import CveMatch
from core.tenant import TenantContext
from db.cves import CveMatchRepo
from db.endpoints import EndpointRepo
from modules.intelligence.cve_feed import fetch_kev, fetch_recent_cves
from modules.intelligence.cve_match import alertable, match_cves


async def run_cve_watch(
    *,
    mongo: Any,
    tenant: TenantContext,
    program_id: str,
    recent=fetch_recent_cves,
    kev=fetch_kev,
) -> dict:
    endpoints = await EndpointRepo.from_mongo(mongo).list(
        tenant.tenant_id, program_id, limit=100_000
    )

    tech_items: list[dict] = []
    for ep in endpoints:
        host = urlsplit(ep["url"]).hostname or ""
        asset_fp = asset_fingerprint(program_id, host)
        for tech in ep.get("tech") or []:
            product, version = parse_tech(tech)
            if product:
                tech_items.append(
                    {
                        "product": product,
                        "version": version,
                        "asset_fingerprint": asset_fp,
                        "location": ep["url"],
                    }
                )

    if not tech_items:
        logger.info("cve-watch {}: skipped (no fingerprinted tech yet)", program_id)
        return {
            "tech_items": 0, "matches": 0, "new_alertable": 0, "alerts": [],
            "skipped": True, "note": "no fingerprinted tech yet — probe endpoints first",
        }

    records = await recent()
    kev_set = await kev()
    matches = match_cves(tech_items, records, kev_set)

    models = [
        CveMatch(
            tenant_id=tenant.tenant_id,
            program_id=program_id,
            fingerprint=cve_match_fingerprint(
                program_id, m["cve_id"], m["asset_fingerprint"], m["cpe"]
            ),
            cve_id=m["cve_id"],
            cpe=m["cpe"],
            asset_fingerprint=m["asset_fingerprint"],
            cvss=m["cvss"],
            on_kev=m["on_kev"],
            confidence=m["confidence"],
            severity=m["severity"],
        )
        for m in matches
    ]
    results = await CveMatchRepo.from_mongo(mongo).upsert_all(models)

    alerts = [
        {
            "cve_id": mo.cve_id,
            "severity": mo.severity.value,
            "on_kev": mo.on_kev,
            "confidence": mo.confidence,
            "asset_fingerprint": mo.asset_fingerprint,
        }
        for mo, res, raw in zip(models, results, matches, strict=True)
        if res.inserted and alertable(raw)
    ]

    logger.info(
        "cve-watch {}: {} tech items, {} matches, {} new alertable",
        program_id,
        len(tech_items),
        len(models),
        len(alerts),
    )
    return {
        "tech_items": len(tech_items),
        "matches": len(models),
        "new_alertable": len(alerts),
        "alerts": alerts,
    }
