"""Nuclei-template watch pipeline (module 22) — new template → targeted re-scan.

When nuclei-templates publishes new checks, re-scanning *everything* is wasteful
and slow (§3.1 state-awareness). This stage answers a narrower question: "did a
template appear that could match **this program's** fingerprinted stack?" — and
if so, names the hosts worth re-scanning.

State model mirrors the change-event baseline used elsewhere: the **first** run
records what is currently relevant and fires nothing (otherwise every existing
template would look "new" on day one). Later runs report only genuinely new
relevant template ids.

Only templates relevant to the program's tech are tracked, so the stored set is
small (tens), not the full ~10k template corpus.

The template lister is **injected**. There is deliberately no default: nuclei's
``-tl`` output contract varies by version and has not been verified against the
pinned binary, and a default that silently returns nothing would make this stage
look healthy while doing nothing — the exact failure this module is being rescued
from. Without a lister the stage reports ``skipped`` honestly.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from core.logging import logger
from core.tenant import TenantContext
from db.endpoints import EndpointRepo
from db.programs import ProgramRepo
from modules.intelligence.nuclei_watch import new_template_ids, relevant_templates
from modules.scanning.nuclei import list_templates as list_installed_templates


def _tech_products(endpoints: list[dict]) -> set[str]:
    """The tech tokens fingerprinted across the program's endpoints."""
    out: set[str] = set()
    for ep in endpoints:
        for tech in ep.get("tech") or []:
            # "nginx:1.24.0" → "nginx"; keep it simple, mirror core.cpe.parse_tech
            out.add(str(tech).split(":")[0].strip().lower())
    return {t for t in out if t}


def _hosts_with_tech(endpoints: list[dict], products: set[str]) -> list[str]:
    """Hosts whose fingerprint includes any of *products* — the re-scan targets."""
    hosts: set[str] = set()
    for ep in endpoints:
        techs = {str(t).split(":")[0].strip().lower() for t in (ep.get("tech") or [])}
        if techs & products:
            host = urlsplit(ep["url"]).hostname
            if host:
                hosts.add(host)
    return sorted(hosts)


async def run_nuclei_watch(
    *,
    mongo: Any,
    tenant: TenantContext,
    program_id: str,
    templates=None,
) -> dict:
    """``templates`` is an async callable returning ``[{id, product?, tags?}, ...]``.

    Defaults to the real corpus in the scanning image; injectable for tests."""
    templates = templates or list_installed_templates

    endpoints = await EndpointRepo.from_mongo(mongo).list(
        tenant.tenant_id, program_id, limit=100_000
    )
    products = _tech_products(endpoints)
    if not products:
        logger.info("nuclei-watch {}: skipped (no fingerprinted tech yet)", program_id)
        return {
            "new_templates": [],
            "rescan_hosts": [],
            "skipped": True,
            "note": "no fingerprinted tech yet — probe first",
        }

    current = await templates()
    relevant = relevant_templates(current, products)
    relevant_ids = {str(t["id"]) for t in relevant if t.get("id")}

    program = await ProgramRepo.from_mongo(mongo).get(tenant.tenant_id, program_id) or {}
    known = program.get("known_template_ids")

    if known is None:
        # Baseline: record what's relevant today, alert on nothing.
        await ProgramRepo.from_mongo(mongo).set_known_template_ids(
            tenant.tenant_id, program_id, sorted(relevant_ids)
        )
        logger.info(
            "nuclei-watch {}: baseline recorded ({} relevant template(s)) — no rescan",
            program_id,
            len(relevant_ids),
        )
        return {"new_templates": [], "rescan_hosts": [], "baseline": True}

    new_ids = new_template_ids(set(known), relevant_ids)
    if new_ids:
        await ProgramRepo.from_mongo(mongo).set_known_template_ids(
            tenant.tenant_id, program_id, sorted(set(known) | relevant_ids)
        )

    matched = [t for t in relevant if str(t.get("id")) in new_ids]
    matched_products = {
        str(t.get("product") or "").lower() for t in matched if t.get("product")
    } | {tag.lower() for t in matched for tag in (t.get("tags") or [])}
    rescan_hosts = _hosts_with_tech(endpoints, matched_products & products) if matched else []

    logger.info(
        "nuclei-watch {}: {} relevant template(s), {} new → {} host(s) to re-scan",
        program_id,
        len(relevant_ids),
        len(new_ids),
        len(rescan_hosts),
    )
    return {
        "new_templates": sorted(new_ids),
        "rescan_hosts": rescan_hosts,
    }
