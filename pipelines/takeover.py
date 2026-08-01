"""Subdomain-takeover pipeline — dangling-CNAME hosts → HIGH findings.

Runs after DNS enrichment: for every asset that has a CNAME, check whether it points
at an unclaimed known service (HTTP fingerprint or dangling target). A hit is a real,
high-impact exposure (an attacker can serve content from your subdomain), so it's
recorded as a Finding and flagged on the asset for the DNS page.
"""

from __future__ import annotations

import asyncio
from typing import Any
from urllib.parse import urlsplit

from core.hashing import finding_fingerprint
from core.logging import logger
from core.models import Finding
from core.ratelimit import PolitenessLimiter, throttled_fetch
from core.scope import ProgramScope, ScopeEngine
from core.severity import Severity
from core.tenant import TenantContext
from db.assets import AssetRepo
from db.endpoints import EndpointRepo
from db.findings import FindingRepo
from modules.recon.dnsx import resolve_one as dnsx_resolve_one
from modules.takeover import check_host, default_fetch, find_dangling_a_records

CONCURRENCY = 10


async def run_takeover(
    *,
    mongo: Any,
    engine: ScopeEngine,
    scope: ProgramScope,
    tenant: TenantContext,
    program_id: str,
    timeout: float,
    fetch=default_fetch,
    resolve=dnsx_resolve_one,
    limiter: PolitenessLimiter | None = None,
) -> dict:
    tid = tenant.tenant_id
    # This stage makes in-process HTTP requests straight at customer hosts, and ran
    # unthrottled until ADR-0012 — the limiter existed but nothing ever called it.
    # Wrapping the injected fetch paces every probe without touching the module.
    if limiter is not None:
        fetch = throttled_fetch(fetch, limiter)
    assets = await AssetRepo.from_mongo(mongo).list(tid, program_id, limit=100_000)
    # Check any host that resolves — a CNAME (dangling / claimable target) OR an A record
    # (S3 fronted by CloudFront has no telltale CNAME but its body says "NoSuchBucket").
    candidates = [
        a
        for a in assets
        if a.get("monitored", True)
        and ((a.get("dns_records") or {}).get("cname") or a.get("resolved_ips"))
    ]
    if not candidates:
        return {
            "checked": 0,
            "vulnerable": 0,
            "new": 0,
            "skipped": True,
            "note": "no resolving hosts to check",
        }

    logger.info("takeover: body-checking {} resolving host(s)", len(candidates))
    sem = asyncio.Semaphore(CONCURRENCY)
    repo = AssetRepo.from_mongo(mongo)

    async def _check(asset: dict) -> tuple[dict, dict | None]:
        cnames = (asset.get("dns_records") or {}).get("cname") or []
        async with sem:
            try:
                hit = await check_host(asset["hostname"], cnames, fetch=fetch, resolve=resolve)
            except Exception as exc:  # noqa: BLE001 - one host must not sink the stage
                logger.warning("takeover check failed for {}: {}", asset["hostname"], exc)
                hit = None
        return asset, hit

    results = await asyncio.gather(*(_check(a) for a in candidates))

    findings: list[Finding] = []
    vulnerable = 0
    for asset, hit in results:
        service = hit["service"] if hit else None
        # keep the asset flag in sync (set on hit, clear on none — self-healing)
        await repo.set_flag(tid, asset["fingerprint"], "takeover_risk", service)
        if not hit:
            continue
        vulnerable += 1
        host = hit["host"]
        findings.append(
            Finding(
                tenant_id=tid,
                program_id=program_id,
                fingerprint=finding_fingerprint(program_id, "subdomain-takeover", host),
                check_id="subdomain-takeover",
                module="takeover",
                location=host,
                name=f"Possible subdomain takeover ({hit['service']})",
                description=(
                    f"{host} has a dangling CNAME to {hit['cname']} ({hit['service']}). "
                    f"Evidence: {hit['evidence']}. An attacker may be able to claim the "
                    f"target service and serve content from this subdomain."
                ),
                severity=Severity.HIGH,
            )
        )

    # Dangling A-records: same class, different record type. Purely analytical — it
    # reads the DNS and probe results already collected, so it costs no extra requests.
    endpoints = await EndpointRepo.from_mongo(mongo).list(tid, program_id, limit=100_000)
    alive = {
        (urlsplit(e.get("url") or "").hostname or "").lower()
        for e in endpoints
        if e.get("status_code")
    }
    dangling = find_dangling_a_records(
        assets, classify=lambda ip: engine.classify_ip(ip).value, alive_hosts=alive
    )
    for record in dangling:
        logger.info(
            "takeover: {} → {} is pooled {} with nothing answering",
            record.host,
            record.ip,
            record.ip_class,
        )
        findings.append(
            Finding(
                tenant_id=tid,
                program_id=program_id,
                fingerprint=finding_fingerprint(program_id, "dangling-a-record", record.host),
                check_id="dangling-a-record",
                module="takeover",
                location=record.host,
                locator=record.ip,
                name=f"Dangling A record to unclaimed cloud address: {record.host}",
                description=record.evidence,
                # MEDIUM, not HIGH: unlike a CNAME you cannot reliably claim a specific
                # pooled address on demand, so the exposure is real but opportunistic.
                severity=Severity.MEDIUM,
                reproduction=f"dig +short {record.host}   # then check whether anything answers",
                raw={
                    "ip": record.ip,
                    "ip_class": record.ip_class,
                    "remediation": record.remediation,
                },
            )
        )

    _, new = await FindingRepo.from_mongo(mongo).upsert_many(findings)
    logger.info(
        "takeover {}: {} checked, {} vulnerable, {} new",
        program_id,
        len(candidates),
        vulnerable,
        new,
    )
    return {"checked": len(candidates), "vulnerable": vulnerable, "new": new}
