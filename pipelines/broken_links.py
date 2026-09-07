"""Broken-link hijacking stage.

Collects the outbound links the site publishes (from crawled endpoints and mined JS),
then checks whether any destination is dead in a way an attacker can take over: an
unregistered domain, or a social handle that 404s. Both give an attacker content served
under the operator's trust.

Purely passive with respect to the operator: we resolve third-party names and read a
status code from a third-party site. Nothing is registered, claimed, or exploited.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from core.hashing import finding_fingerprint
from core.logging import logger
from core.models import Finding
from core.ratelimit import PolitenessLimiter
from core.scope import ProgramScope
from core.tenant import TenantContext
from db.endpoints import EndpointRepo
from db.findings import FindingRepo
from db.jsfiles import JsFileRepo
from modules.scanning import broken_links as blh

#: Bound the work: outbound links are long-tailed and mostly to the same few domains.
MAX_LINKS = 400


async def run_broken_links(
    *,
    mongo: Any,
    scope: ProgramScope,
    tenant: TenantContext,
    program_id: str,
    timeout: float = 15.0,
    limiter: PolitenessLimiter | None = None,
    resolve=None,
    fetch_status=None,
) -> dict:
    """Find outbound links whose destination can be taken over."""
    resolve = resolve or _default_resolve
    fetch_status = fetch_status or _default_status
    if limiter is not None:
        fetch_status = _throttled(fetch_status, limiter)

    own = tuple(scope.verified_apexes)

    # Outbound links come from two places: absolute URLs we mined out of JS, and any
    # discovered endpoint that points off-site.
    candidates: dict[str, str] = {}  # url -> where we saw it
    for js in await JsFileRepo.from_mongo(mongo).list(tenant.tenant_id, program_id, limit=10_000):
        for item in js.get("items") or []:
            url = item.get("absolute") or ""
            if url.startswith("http") and blh.is_external(url, own):
                candidates.setdefault(url, js.get("url", ""))
    ep_repo = EndpointRepo.from_mongo(mongo)
    for ep in await ep_repo.list(tenant.tenant_id, program_id, limit=100_000):
        url = ep.get("url") or ""
        if url.startswith("http") and blh.is_external(url, own):
            candidates.setdefault(url, url)

    if not candidates:
        logger.info("broken_links: no outbound links discovered yet")
        return {"skipped": True, "note": "no outbound links found — run a crawl first"}

    # One check per external host is enough for the domain signal; keep every distinct
    # social profile URL, since those are per-handle.
    ordered = sorted(candidates.items())[:MAX_LINKS]
    checked_hosts: set[str] = set()
    findings: list[Finding] = []
    hijackable = 0

    for url, found_on in ordered:
        host = urlsplit(url).hostname or ""
        is_social = blh.social_platform(url) is not None
        if not is_social:
            if host in checked_hosts:
                continue
            checked_hosts.add(host)
        try:
            link = await blh.check_link(
                url, found_on, resolve=resolve, fetch_status=fetch_status if is_social else None
            )
        except Exception as exc:  # noqa: BLE001 - one bad link never sinks the stage
            logger.debug("broken_links: check failed for {}: {}", url, exc)
            continue
        if link is None:
            continue
        hijackable += 1
        findings.append(
            Finding(
                tenant_id=tenant.tenant_id,
                program_id=program_id,
                fingerprint=finding_fingerprint(program_id, f"blh-{link.kind}", link.url),
                check_id=f"broken-link-{link.kind}",
                module="broken_links",
                location=link.found_on,
                locator=link.url,
                name=(
                    f"Broken link hijack: {link.target_host} is unregistered"
                    if link.kind == "unregistered-domain"
                    else f"Broken link hijack: unclaimed {link.platform} handle"
                ),
                description=link.evidence,
                severity=link.severity,
                reproduction=(
                    f"dig +short {link.target_host}   # no answer = registerable"
                    if link.kind == "unregistered-domain"
                    else f"curl -sI {link.url}   # 404 = handle is free to claim"
                ),
                raw={
                    "dead_link": link.url,
                    "linked_from": link.found_on,
                    "kind": link.kind,
                    "platform": link.platform,
                    "remediation": blh.remediation(link),
                },
            )
        )

    total, new = await FindingRepo.from_mongo(mongo).upsert_many(findings)
    logger.info(
        "broken_links: {} outbound link(s) checked → {} hijackable ({} new)",
        len(ordered),
        hijackable,
        new,
    )
    return {"checked": len(ordered), "hijackable": hijackable, "findings": total, "new": new}


def _throttled(fetch_status, limiter: PolitenessLimiter):
    async def _f(url: str) -> int:
        await limiter.acquire(urlsplit(url).hostname or url)
        return await fetch_status(url)

    return _f


async def _default_resolve(host: str) -> list[str]:  # pragma: no cover - real DNS
    from modules.recon.dnsx import resolve_hosts

    return (await resolve_hosts([host], 15.0)).get(host, [])


async def _default_status(url: str) -> int:  # pragma: no cover - real network
    import aiohttp

    from modules.safe_http import assert_url_allowed, guarded_session

    assert_url_allowed(url)
    async with guarded_session() as session:
        async with session.get(
            url, timeout=aiohttp.ClientTimeout(total=15), ssl=False, allow_redirects=False
        ) as resp:
            return resp.status
