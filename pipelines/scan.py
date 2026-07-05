"""Scan pipeline — endpoints → findings (module 7, nuclei safe policy).

The scope decision per endpoint chooses the scan intensity, enforcing §9b/§9d:

* ACTIVE_SCAN permitted (confirmed-dedicated IPs) → aggressive template set.
* HTTP_PROBE only (CDN/cloud-shared/unconfirmed) → safe templates.
* not even HTTP_PROBE → skipped.

All runs exclude the harmful ``dos,intrusive,fuzz`` tags (enforced in the wrapper).
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from core.hashing import finding_fingerprint
from core.logging import logger
from core.models import Finding
from core.scope import Action, ProgramScope, ScopeEngine
from core.severity import Severity
from core.tenant import TenantContext
from db.assets import AssetRepo
from db.endpoints import EndpointRepo
from db.findings import FindingRepo
from modules.scanning.nuclei import scan as nuclei_scan


def _severity(value: str) -> Severity:
    try:
        return Severity(value)
    except ValueError:
        return Severity.INFO


async def run_scan(
    *,
    mongo: Any,
    engine: ScopeEngine,
    scope: ProgramScope,
    tenant: TenantContext,
    program_id: str,
    timeout: float,
    scan=nuclei_scan,
) -> dict:
    tid = tenant.tenant_id
    assets = await AssetRepo.from_mongo(mongo).list(tid, program_id, limit=100_000)
    ips_by_host = {a["hostname"]: a.get("resolved_ips", []) for a in assets}
    endpoints = await EndpointRepo.from_mongo(mongo).list(tid, program_id, limit=100_000)

    safe_urls: list[str] = []
    aggressive_urls: list[str] = []
    for ep in endpoints:
        host = urlsplit(ep["url"]).hostname or ""
        decision = engine.evaluate(host, ips_by_host.get(host, []), scope)
        if not decision.permits(Action.HTTP_PROBE):
            continue
        (aggressive_urls if decision.permits(Action.ACTIVE_SCAN) else safe_urls).append(ep["url"])

    if not safe_urls and not aggressive_urls:
        logger.info("scan {}: nothing to scan (no endpoints yet)", program_id)
        return {
            "scanned_safe": 0, "scanned_aggressive": 0, "findings": 0, "new": 0, "new_findings": [],
            "skipped": True, "note": "no endpoints to scan yet — probe/crawl first",
        }

    raw: list[dict] = []
    if safe_urls:
        raw += await scan(safe_urls, timeout, aggressive=False)
    if aggressive_urls:
        raw += await scan(aggressive_urls, timeout, aggressive=True)

    models = [
        Finding(
            tenant_id=tenant.tenant_id,
            program_id=program_id,
            fingerprint=finding_fingerprint(program_id, f["template_id"], f["matched_at"]),
            check_id=f["template_id"],
            module="nuclei",
            location=f["matched_at"],
            name=f["name"] or f["template_id"],
            description=f["description"],
            severity=_severity(f["severity"]),
            references=f.get("reference") or [],
            raw=f.get("raw") or {},
        )
        for f in raw
    ]
    res = await FindingRepo.from_mongo(mongo).upsert_all(models)
    new_findings = [
        {"name": m.name, "severity": m.severity.value, "location": m.location}
        for m, x in zip(models, res, strict=True)
        if x.inserted
    ]

    logger.info(
        "scan {}: {} safe + {} aggressive urls, {} findings, {} new",
        program_id,
        len(safe_urls),
        len(aggressive_urls),
        len(models),
        len(new_findings),
    )
    return {
        "scanned_safe": len(safe_urls),
        "scanned_aggressive": len(aggressive_urls),
        "findings": len(models),
        "new": len(new_findings),
        "new_findings": new_findings,
    }
