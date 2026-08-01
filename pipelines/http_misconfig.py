"""HTTP misconfiguration stage — CORS, open redirect, WAF context.

One extra request per check against endpoints we already discovered and probed. Nothing
here exploits: the CORS check reads two response headers, the redirect check reads a
Location header without following it, and the WAF check reads headers we already have.
"""

from __future__ import annotations

import asyncio
from typing import Any
from urllib.parse import urlsplit

from core.hashing import finding_fingerprint
from core.logging import logger
from core.models import Finding
from core.ratelimit import PolitenessLimiter
from core.scope import Action, ProgramScope, ScopeEngine
from core.tenant import TenantContext
from db.assets import AssetRepo
from db.endpoints import EndpointRepo
from db.findings import FindingRepo
from modules.scanning import http_misconfig as mis

#: CORS is per-origin; redirects are per-URL. Both bounded so a huge surface stays polite.
MAX_ORIGINS = 60
MAX_REDIRECT_URLS = 150
CONCURRENCY = 8


async def run_http_misconfig(
    *,
    mongo: Any,
    engine: ScopeEngine,
    scope: ProgramScope,
    tenant: TenantContext,
    program_id: str,
    timeout: float = 20.0,
    limiter: PolitenessLimiter | None = None,
    fetch_headers=None,
) -> dict:
    fetch_headers = fetch_headers or _default_fetch_headers
    if limiter is not None:
        fetch_headers = _throttled(fetch_headers, limiter)

    assets = await AssetRepo.from_mongo(mongo).list(tenant.tenant_id, program_id, limit=100_000)
    ips_by_host = {a["hostname"]: a.get("resolved_ips", []) for a in assets}
    endpoints = await EndpointRepo.from_mongo(mongo).list(
        tenant.tenant_id, program_id, limit=100_000
    )

    def allowed(host: str) -> bool:
        return (
            bool(host)
            and scope.owns_host(host)
            and engine.evaluate(host, ips_by_host.get(host, []), scope).permits(Action.HTTP_PROBE)
        )

    origins: dict[str, str] = {}
    redirect_targets: list[tuple[str, str]] = []
    for ep in endpoints:
        url = ep.get("url") or ""
        parts = urlsplit(url)
        host = parts.hostname or ""
        if not parts.scheme or not allowed(host):
            continue
        if host not in origins and len(origins) < MAX_ORIGINS:
            origins[host] = f"{parts.scheme}://{parts.netloc}"
        if len(redirect_targets) < MAX_REDIRECT_URLS:
            redirect_targets.extend(mis.redirect_candidates(url))

    if not origins:
        logger.info("http_misconfig: no alive in-scope origins yet")
        return {"skipped": True, "note": "no live hosts found — run a probe first"}

    logger.info(
        "http_misconfig: {} origin(s) for CORS, {} redirect candidate(s)",
        len(origins),
        len(redirect_targets),
    )

    sem = asyncio.Semaphore(CONCURRENCY)
    findings: list[Finding] = []
    protected = unprotected = 0

    async def check_origin(origin: str) -> None:
        nonlocal protected, unprotected
        async with sem:
            try:
                status, headers = await fetch_headers(origin, {"Origin": mis.PROBE_ORIGIN})
            except Exception as exc:  # noqa: BLE001 - one host must not sink the stage
                logger.debug("http_misconfig: {} failed: {}", origin, exc)
                return
        waf = mis.fingerprint_waf(origin, headers)
        if waf.protected:
            protected += 1
            logger.info("http_misconfig: {} is behind {}", origin, ", ".join(waf.products))
        else:
            unprotected += 1

        verdict = mis.analyse_cors(origin, headers)
        logger.info(
            "http_misconfig: CORS {} → allow-origin={!r} credentials={}",
            origin,
            verdict.allow_origin or "(none)",
            verdict.allow_credentials,
        )
        if not verdict.vulnerable:
            return
        findings.append(
            Finding(
                tenant_id=tenant.tenant_id,
                program_id=program_id,
                fingerprint=finding_fingerprint(program_id, f"cors-{verdict.kind}", origin),
                check_id=f"cors-{verdict.kind}",
                module="http_misconfig",
                location=origin,
                locator=verdict.allow_origin,
                name=f"CORS policy accepts an arbitrary origin ({verdict.kind})",
                description=verdict.evidence,
                severity=verdict.severity,
                reproduction=(
                    f"curl -s -I {origin} -H 'Origin: {mis.PROBE_ORIGIN}' | grep -i access-control"
                ),
                raw={
                    "allow_origin": verdict.allow_origin,
                    "allow_credentials": verdict.allow_credentials,
                    "waf": list(waf.products),
                },
            )
        )

    async def check_redirect(param: str, probe_url: str) -> None:
        async with sem:
            try:
                status, headers = await fetch_headers(probe_url, None)
            except Exception as exc:  # noqa: BLE001
                logger.debug("http_misconfig: redirect probe failed for {}: {}", probe_url, exc)
                return
        verdict = mis.analyse_redirect(probe_url, param, status, headers)
        if not verdict.vulnerable:
            return
        logger.info("http_misconfig: open redirect via ?{} on {}", param, probe_url)
        findings.append(
            Finding(
                tenant_id=tenant.tenant_id,
                program_id=program_id,
                fingerprint=finding_fingerprint(program_id, "open-redirect", probe_url),
                check_id="open-redirect",
                module="http_misconfig",
                location=probe_url,
                locator=param,
                name=f"Open redirect via ?{param}=",
                description=verdict.evidence,
                severity=verdict.severity,
                reproduction=f"curl -sI '{probe_url}' | grep -i location",
                raw={"param": param, "location": verdict.location},
            )
        )

    await asyncio.gather(
        *(check_origin(o) for o in origins.values()),
        *(check_redirect(p, u) for p, u in redirect_targets),
        return_exceptions=True,
    )

    total, new = await FindingRepo.from_mongo(mongo).upsert_many(findings)
    logger.info(
        "http_misconfig: {} finding(s) ({} new) · {} host(s) behind a WAF, {} without",
        len(findings),
        new,
        protected,
        unprotected,
    )
    return {
        "origins": len(origins),
        "redirects_tested": len(redirect_targets),
        "waf_protected": protected,
        "waf_unprotected": unprotected,
        "findings": total,
        "new": new,
    }


def _throttled(fn, limiter: PolitenessLimiter):
    async def _f(url: str, headers):
        await limiter.acquire(urlsplit(url).hostname or url)
        return await fn(url, headers)

    return _f


async def _default_fetch_headers(url: str, headers: dict | None):  # pragma: no cover - network
    import aiohttp

    from modules.safe_http import assert_url_allowed, guarded_session

    assert_url_allowed(url)
    async with guarded_session() as session:
        async with session.get(
            url,
            headers=headers or {},
            timeout=aiohttp.ClientTimeout(total=15),
            ssl=False,
            allow_redirects=False,  # we READ Location; we never follow it
        ) as resp:
            return resp.status, dict(resp.headers)
