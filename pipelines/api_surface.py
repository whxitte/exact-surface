"""API-surface stage — read what each live host publishes about itself.

robots.txt, sitemap.xml, API schemas, GraphQL introspection and `.well-known`. All
plain GETs (plus one POST carrying the standard GraphQL introspection query) against
hosts already confirmed in scope and alive. Every path discovered is upserted as an
Endpoint so content discovery and nuclei test it on the next run — the same compounding
loop js_mine feeds.
"""

from __future__ import annotations

import asyncio
from typing import Any
from urllib.parse import urljoin, urlsplit

from core.hashing import endpoint_fingerprint, finding_fingerprint
from core.logging import logger
from core.models import Endpoint, Finding
from core.ratelimit import PolitenessLimiter
from core.scope import Action, ProgramScope, ScopeEngine
from core.severity import Severity
from core.tenant import TenantContext
from db.assets import AssetRepo
from db.endpoints import EndpointRepo
from db.findings import FindingRepo
from modules.scanning import api_surface as api

#: Hosts probed per run. The checks are per-origin, not per-URL, so this is the real
#: unit of work — a few requests each against the alive front doors.
MAX_HOSTS = 60
#: Bound concurrent hosts; the politeness limiter still paces per-host requests.
CONCURRENCY = 6


async def run_api_surface(
    *,
    mongo: Any,
    engine: ScopeEngine,
    scope: ProgramScope,
    tenant: TenantContext,
    program_id: str,
    timeout: float = 20.0,
    limiter: PolitenessLimiter | None = None,
    fetch=None,
    post=None,
) -> dict:
    """Mine each alive in-scope origin for the surface it advertises."""
    fetch = fetch or _default_fetch
    post = post or _default_post
    if limiter is not None:
        fetch, post = _throttled(fetch, limiter), _throttled(post, limiter)

    assets = await AssetRepo.from_mongo(mongo).list(tenant.tenant_id, program_id, limit=100_000)
    ips_by_host = {a["hostname"]: a.get("resolved_ips", []) for a in assets}

    ep_repo = EndpointRepo.from_mongo(mongo)
    endpoints = await ep_repo.list(tenant.tenant_id, program_id, limit=100_000)

    origins: dict[str, str] = {}
    for ep in endpoints:
        url = ep.get("url") or ""
        parts = urlsplit(url)
        if not parts.scheme or not parts.hostname:
            continue
        host = parts.hostname
        if host in origins or not scope.owns_host(host):
            continue
        if not engine.evaluate(host, ips_by_host.get(host, []), scope).permits(Action.HTTP_PROBE):
            continue
        origins[host] = f"{parts.scheme}://{parts.netloc}"
        if len(origins) >= MAX_HOSTS:
            break

    if not origins:
        logger.info("api_surface: no alive in-scope origins yet")
        return {"skipped": True, "note": "no live hosts found — run a probe first"}

    logger.info("api_surface: inspecting {} origin(s)", len(origins))
    sem = asyncio.Semaphore(CONCURRENCY)
    results = await asyncio.gather(
        *(_inspect(o, fetch, post, sem) for o in origins.values()), return_exceptions=True
    )

    new_endpoints: list[Endpoint] = []
    findings: list[Finding] = []
    known = {ep.get("url") for ep in endpoints}
    counts = {"robots": 0, "sitemap": 0, "schemas": 0, "graphql": 0, "well_known": 0}

    for origin, result in zip(origins.values(), results, strict=False):
        if isinstance(result, BaseException):
            logger.debug("api_surface: {} failed: {}", origin, result)
            continue
        paths, schemas = result

        for disc in paths:
            counts[disc.source] = counts.get(disc.source, 0) + 1
            if disc.path in known:
                continue
            host = urlsplit(disc.path).hostname or ""
            if not scope.owns_host(host):
                continue  # a sitemap may list third-party URLs; those are not ours
            known.add(disc.path)
            new_endpoints.append(
                Endpoint(
                    tenant_id=tenant.tenant_id,
                    program_id=program_id,
                    fingerprint=endpoint_fingerprint(program_id, "GET", disc.path),
                    url=disc.path,
                    source=disc.source,
                    risk_tags=["hidden"] if disc.interesting else [],
                )
            )

        hidden = [d for d in paths if d.interesting and d.source == "robots"]
        if hidden:
            findings.append(
                Finding(
                    tenant_id=tenant.tenant_id,
                    program_id=program_id,
                    fingerprint=finding_fingerprint(program_id, "robots-hidden", origin),
                    check_id="robots-discloses-sensitive-paths",
                    module="api_surface",
                    location=f"{origin}/robots.txt",
                    locator=hidden[0].path,
                    name=f"robots.txt lists {len(hidden)} sensitive path(s)",
                    description=(
                        "robots.txt asks search engines not to index these paths, which "
                        "tells anyone who reads the file exactly where they are. It is a "
                        "public file and it is the first thing an attacker opens.\n\n"
                        + "\n".join(f"  {d.path}" for d in hidden[:20])
                    ),
                    severity=Severity.LOW,
                    reproduction=f"curl -s {origin}/robots.txt",
                    raw={"paths": [d.path for d in hidden[:50]]},
                )
            )

        for schema in schemas:
            counts["graphql" if schema.kind == "graphql" else "schemas"] += 1
            if schema.severity is Severity.INFO and schema.kind == "well-known":
                continue  # recorded as surface, not worth a finding row
            findings.append(
                Finding(
                    tenant_id=tenant.tenant_id,
                    program_id=program_id,
                    fingerprint=finding_fingerprint(program_id, f"api-{schema.kind}", schema.url),
                    check_id=f"api-surface-{schema.kind}",
                    module="api_surface",
                    location=schema.url,
                    locator=schema.kind,
                    name=(
                        "GraphQL introspection enabled"
                        if schema.kind == "graphql"
                        else "API schema publicly served"
                    ),
                    description=schema.detail,
                    severity=schema.severity,
                    reproduction=(
                        f"curl -s -X POST {schema.url} -H 'content-type: application/json' "
                        f"-d '{{\"query\":\"{api.INTROSPECTION_QUERY}\"}}'"
                        if schema.kind == "graphql"
                        else f"curl -s {schema.url}"
                    ),
                    raw={"kind": schema.kind, "endpoints": list(schema.endpoints[:100])},
                )
            )

    ep_total, ep_new = await ep_repo.upsert_many(new_endpoints)
    f_total, f_new = await FindingRepo.from_mongo(mongo).upsert_many(findings)
    logger.info(
        "api_surface: {} robots + {} sitemap path(s), {} schema(s), {} graphql "
        "→ {} new endpoint(s)",
        counts["robots"], counts["sitemap"], counts["schemas"], counts["graphql"], ep_new,
    )
    return {
        "origins": len(origins),
        "robots_paths": counts["robots"],
        "sitemap_paths": counts["sitemap"],
        "schemas": counts["schemas"],
        "graphql": counts["graphql"],
        "endpoints": ep_total,
        "new": ep_new,
        "findings": f_new,
    }


async def _inspect(origin: str, fetch, post, sem: asyncio.Semaphore):
    """One origin: robots + sitemap + schema paths + graphql + well-known."""
    async with sem:
        paths: list[api.DiscoveredPath] = []
        schemas: list[api.ApiSchema] = []

        status, body, _ = await fetch(urljoin(origin, "/robots.txt"))
        sitemap_urls: list[str] = []
        if status == 200 and body:
            found, sitemap_urls = api.parse_robots(body, origin)
            paths.extend(found)
            logger.info("api_surface: {}/robots.txt → {} path(s)", origin, len(found))

        for sm in (sitemap_urls or [urljoin(origin, "/sitemap.xml")])[:3]:
            status, body, _ = await fetch(sm)
            if status != 200 or not body:
                continue
            if api.is_sitemap_index(body):
                # An index points at more sitemaps; follow a couple, not the whole tree.
                for child in api.parse_sitemap(body, limit=3):
                    cs, cb, _ = await fetch(child.path)
                    if cs == 200 and cb:
                        paths.extend(api.parse_sitemap(cb))
            else:
                paths.extend(api.parse_sitemap(body))

        for path in api.SCHEMA_PATHS:
            url = urljoin(origin, path)
            status, body, ctype = await fetch(url)
            schema = api.analyse_schema(url, status, body, ctype)
            if schema:
                schemas.append(schema)
                logger.info("api_surface: API schema at {}", url)
                break  # one is enough to make the point

        for path in api.GRAPHQL_PATHS:
            url = urljoin(origin, path)
            status, body = await post(url, {"query": api.INTROSPECTION_QUERY})
            schema = api.analyse_graphql(url, status, body)
            if schema:
                schemas.append(schema)
                logger.info("api_surface: GraphQL at {} ({})", url, schema.severity.value)
                break

        for path in api.WELL_KNOWN_PATHS:
            url = urljoin(origin, path)
            status, body, _ = await fetch(url)
            verdict = api.well_known_severity(url, status, body)
            if verdict:
                sev, detail = verdict
                schemas.append(
                    api.ApiSchema(url=url, kind="well-known", detail=detail, severity=sev)
                )

        return paths, schemas


def _throttled(fn, limiter: PolitenessLimiter):
    async def _f(url: str, *args):
        await limiter.acquire(urlsplit(url).hostname or url)
        return await fn(url, *args)

    return _f


async def _default_fetch(url: str):  # pragma: no cover - real network
    import aiohttp

    from modules.safe_http import assert_url_allowed, guarded_session

    assert_url_allowed(url)
    async with guarded_session() as session:
        async with session.get(
            url, timeout=aiohttp.ClientTimeout(total=15), ssl=False, allow_redirects=True
        ) as resp:
            ctype = resp.headers.get("content-type", "")
            body = "" if resp.status != 200 else (await resp.text(errors="ignore"))[:2_000_000]
            return resp.status, body, ctype


async def _default_post(url: str, payload: dict):  # pragma: no cover - real network
    import aiohttp

    from modules.safe_http import assert_url_allowed, guarded_session

    assert_url_allowed(url)
    async with guarded_session() as session:
        async with session.post(
            url,
            json=payload,
            timeout=aiohttp.ClientTimeout(total=15),
            ssl=False,
            allow_redirects=False,
        ) as resp:
            return resp.status, (await resp.text(errors="ignore"))[:500_000]
