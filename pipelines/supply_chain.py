"""Supply-chain stage — dependency-confusion exposure from mined JavaScript.

Reads the bundles js_mine already stored, pulls out the package names inside them, and
asks the public npm registry whether each name is claimed. A 404 means anyone can
publish it, which is how an attacker gets code executed inside the customer's build.

We only ever read registry metadata. Publishing or reserving a name — even defensively —
would be acting on the customer's behalf against a third-party service, which is not
ours to do; the finding tells them to do it themselves.
"""

from __future__ import annotations

import asyncio
from typing import Any

from core.hashing import finding_fingerprint
from core.logging import logger
from core.models import Finding
from core.tenant import TenantContext
from db.findings import FindingRepo
from db.jsfiles import JsFileRepo
from modules.osint import dependency_confusion as dc

CONCURRENCY = 8


async def run_supply_chain(
    *,
    mongo: Any,
    tenant: TenantContext,
    program_id: str,
    timeout: float = 60.0,
    fetch_bundle=None,
    registry_status=None,
) -> dict:
    """Check every internal-looking package name for an unclaimed public registration."""
    fetch_bundle = fetch_bundle or _default_fetch
    registry_status = registry_status or _default_registry_status

    js_files = await JsFileRepo.from_mongo(mongo).list(tenant.tenant_id, program_id, limit=10_000)
    if not js_files:
        logger.info("supply_chain: no mined JavaScript yet")
        return {"skipped": True, "note": "no JavaScript mined — run JavaScript mining first"}

    # Bundle bodies are not stored (they are large and re-fetchable), so re-read the
    # few that matter. Cap hard: package references repeat heavily across chunks.
    packages: dict[str, dc.PackageRef] = {}
    for js in js_files[:40]:
        url = js.get("url") or ""
        try:
            body = await fetch_bundle(url)
        except Exception as exc:  # noqa: BLE001 - a dead bundle must not sink the stage
            logger.debug("supply_chain: fetch failed for {}: {}", url, exc)
            continue
        if not body:
            continue
        for ref in dc.extract_packages(body, url):
            packages.setdefault(ref.name, ref)
        if len(packages) >= dc.MAX_CANDIDATES:
            break

    if not packages:
        logger.info("supply_chain: no internal-looking package names found")
        return {"packages": 0, "unclaimed": 0, "findings": 0, "new": 0}

    logger.info("supply_chain: checking {} package name(s) against npm", len(packages))
    sem = asyncio.Semaphore(CONCURRENCY)
    risks: list[dc.ConfusionRisk] = []

    async def check(ref: dc.PackageRef) -> None:
        async with sem:
            try:
                status = await registry_status(dc.registry_url(ref.name))
            except Exception as exc:  # noqa: BLE001
                logger.debug("supply_chain: registry lookup failed for {}: {}", ref.name, exc)
                return
        logger.info("supply_chain: npm {} → {}", ref.name, status)
        risk = dc.assess(ref, status)
        if risk:
            risks.append(risk)

    await asyncio.gather(*(check(r) for r in packages.values()), return_exceptions=True)

    findings = [
        Finding(
            tenant_id=tenant.tenant_id,
            program_id=program_id,
            fingerprint=finding_fingerprint(program_id, "dep-confusion", risk.package.name),
            check_id="dependency-confusion-unclaimed-package",
            module="supply_chain",
            location=risk.package.found_in,
            locator=risk.package.name,
            name=f"Unclaimed package name referenced in public JS: {risk.package.name}",
            description=risk.evidence,
            severity=risk.severity,
            reproduction=(
                "curl -s -o /dev/null -w '%{http_code}' " + dc.registry_url(risk.package.name)
            ),
            raw={
                "package": risk.package.name,
                "registry": risk.registry,
                "found_in": risk.package.found_in,
                "remediation": risk.remediation,
            },
        )
        for risk in risks
    ]
    total, new = await FindingRepo.from_mongo(mongo).upsert_many(findings)
    logger.info(
        "supply_chain: {}/{} package name(s) are unclaimed on npm ({} new)",
        len(risks),
        len(packages),
        new,
    )
    return {
        "packages": len(packages),
        "unclaimed": len(risks),
        "findings": total,
        "new": new,
    }


async def _default_fetch(url: str) -> str:  # pragma: no cover - real network
    import aiohttp

    from modules.safe_http import assert_url_allowed, guarded_session

    assert_url_allowed(url)
    async with guarded_session() as session:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=20), ssl=False) as resp:
            if resp.status != 200:
                return ""
            return (await resp.text(errors="ignore"))[:5_000_000]


async def _default_registry_status(url: str) -> int:  # pragma: no cover - real network
    import aiohttp

    from modules.safe_http import assert_url_allowed, guarded_session

    assert_url_allowed(url)
    async with guarded_session() as session:
        async with session.head(
            url, timeout=aiohttp.ClientTimeout(total=15), allow_redirects=True
        ) as resp:
            return resp.status
