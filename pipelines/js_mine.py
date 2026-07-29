"""JS mining stage — read the app's own JavaScript the way a bug hunter does.

Takes the JavaScript URLs discovered by crawling, fetches each bundle, and extracts the
paths, hostnames and source-map references inside it. Three things come out:

1. **A browsable record per bundle** (``JsFile``) so the user can see exactly what was
   found and in which file — the transparency the product is sold on.
2. **New endpoints**, upserted with ``source="js"`` so they flow into probing, content
   discovery and nuclei on the next run. This is the compounding effect: the app tells
   us its own routes, and the rest of the pipeline then tests them.
3. **Findings** for genuinely notable results — a published source map, or admin/internal
   routes discovered in client-side code.

Safety: only in-scope hosts are fetched, every request goes through the SSRF-safe
guarded session, and the politeness limiter paces them. Reading a JS file the browser
already downloads is as passive as browsing the site.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from core.hashing import endpoint_fingerprint, finding_fingerprint
from core.logging import logger
from core.models import Endpoint, Finding, JsFile
from core.ratelimit import PolitenessLimiter
from core.scope import Action, ProgramScope, ScopeEngine
from core.severity import Severity
from core.tenant import TenantContext
from db.assets import AssetRepo
from db.endpoints import EndpointRepo
from db.findings import FindingRepo
from db.jsfiles import JsFileRepo
from modules.scanning import js_miner

#: Cap per run. A big SPA can ship hundreds of chunks; mining the largest few finds
#: essentially everything, and this bounds both time and memory.
MAX_FILES = 150
#: Bundles above this are almost always vendor blobs; skip rather than burn memory.
MAX_BYTES = 5_000_000
#: Tags that justify raising a Finding rather than just recording the path.
_NOTABLE = frozenset({"admin", "internal", "credentials", "exposure", "graphql", "api-docs"})


async def run_js_mine(
    *,
    mongo: Any,
    engine: ScopeEngine,
    scope: ProgramScope,
    tenant: TenantContext,
    program_id: str,
    timeout: float = 20.0,
    limiter: PolitenessLimiter | None = None,
    fetch=None,
) -> dict:
    """Mine every in-scope JavaScript file discovered so far."""
    fetch = fetch or _default_fetch
    if limiter is not None:
        fetch = _throttled(fetch, limiter)

    ep_repo = EndpointRepo.from_mongo(mongo)
    endpoints = await ep_repo.list(tenant.tenant_id, program_id, limit=100_000)

    # Candidate bundles: anything ending .js that we've seen, in scope, not a library.
    candidates: list[str] = []
    seen: set[str] = set()
    for ep in endpoints:
        url = ep.get("url") or ""
        path = urlsplit(url).path.lower()
        if not path.endswith(".js") or url in seen:
            continue
        host = urlsplit(url).hostname or ""
        if not scope.owns_host(host):
            continue  # third-party CDN — not ours to fetch or report on
        if js_miner.is_library_file(url):
            continue
        seen.add(url)
        candidates.append(url)

    if not candidates:
        logger.info("js_mine: no in-scope JavaScript discovered yet")
        return {"skipped": True, "note": "no JavaScript files found — run a crawl first"}

    # Only fetch from hosts scope permits us to contact.
    assets = await AssetRepo.from_mongo(mongo).list(tenant.tenant_id, program_id, limit=100_000)
    ips_by_host = {a["hostname"]: a.get("resolved_ips", []) for a in assets}
    allowed = []
    for url in candidates:
        host = urlsplit(url).hostname or ""
        if engine.evaluate(host, ips_by_host.get(host, []), scope).permits(Action.HTTP_PROBE):
            allowed.append(url)
    candidates = allowed[:MAX_FILES]

    own_domains = tuple(scope.verified_apexes)
    mined: list[js_miner.MinedFile] = []
    records: list[JsFile] = []

    for url in candidates:
        try:
            body = await fetch(url)
        except Exception as exc:  # noqa: BLE001 - one bad file must not stop the stage
            logger.debug("js_mine: fetch failed for {}: {}", url, exc)
            continue
        if not body or len(body) > MAX_BYTES:
            continue
        result = js_miner.mine(body, url, own_domains=own_domains)
        mined.append(result)
        records.append(
            JsFile(
                tenant_id=tenant.tenant_id,
                program_id=program_id,
                fingerprint=endpoint_fingerprint(program_id, "JS", url),
                url=url,
                size=result.size,
                items=[
                    {"value": i.value, "kind": i.kind, "tags": i.tags, "absolute": i.absolute}
                    for i in result.items
                ],
                hostnames=result.hostnames,
                source_map=result.source_map,
                interesting_count=len(result.interesting),
            )
        )
        logger.info(
            "js_mine: {} → {} item(s), {} interesting, {} host(s)",
            url.rsplit("/", 1)[-1],
            len(result.items),
            len(result.interesting),
            len(result.hostnames),
        )

    files_total, files_new = await JsFileRepo.from_mongo(mongo).upsert_many(records)

    # 2) Feed discovered paths back as endpoints — the compounding step.
    known_urls = {ep.get("url") for ep in endpoints}
    new_endpoints: list[Endpoint] = []
    for result in mined:
        origin = f"{urlsplit(result.url).scheme}://{urlsplit(result.url).netloc}"
        for item in result.items:
            if item.kind != "path" or not item.absolute:
                continue
            if item.absolute in known_urls:
                continue
            host = urlsplit(item.absolute).hostname or ""
            if not scope.owns_host(host):
                continue
            known_urls.add(item.absolute)
            new_endpoints.append(
                Endpoint(
                    tenant_id=tenant.tenant_id,
                    program_id=program_id,
                    fingerprint=endpoint_fingerprint(program_id, "GET", item.absolute),
                    url=item.absolute,
                    source="js",  # visible in the Endpoints tab's source filter
                    risk_tags=item.tags,
                )
            )
        _ = origin
    ep_total, ep_new = await ep_repo.upsert_many(new_endpoints)

    # 3) Findings worth a human's attention.
    findings: list[Finding] = []
    for result in mined:
        if result.source_map:
            findings.append(
                Finding(
                    tenant_id=tenant.tenant_id,
                    program_id=program_id,
                    fingerprint=finding_fingerprint(program_id, "js-source-map", result.url),
                    check_id="js-source-map-exposed",
                    module="js_mine",
                    location=result.url,
                    locator=result.source_map,
                    name="Source map published alongside minified JavaScript",
                    description=(
                        "A .map file is served next to this bundle. Anyone can download it "
                        "and reconstruct the original, unminified source — including "
                        "comments, internal file names and logic the minifier was meant "
                        "to obscure."
                    ),
                    severity=Severity.LOW,
                    reproduction=f"curl -s {result.source_map} | head",
                    raw={"bundle": result.url, "source_map": result.source_map},
                )
            )
        for item in result.interesting:
            if not (_NOTABLE & set(item.tags)):
                continue
            findings.append(
                Finding(
                    tenant_id=tenant.tenant_id,
                    program_id=program_id,
                    fingerprint=finding_fingerprint(program_id, "js-route", item.value),
                    check_id="js-sensitive-route",
                    module="js_mine",
                    location=item.absolute or item.value,
                    locator=item.value,
                    name=(
                        "Sensitive route exposed in client-side JavaScript "
                        f"({', '.join(item.tags)})"
                    ),
                    description=(
                        "This path was extracted from a JavaScript bundle the site serves "
                        "to every visitor. Client-side code is public, so an attacker "
                        "reading it learns the route without any guessing."
                    ),
                    severity=Severity.INFO,
                    reproduction=f"curl -s {result.url} | grep -o '{item.value}'",
                    raw={"found_in": result.url, "tags": item.tags},
                )
            )
    f_total, f_new = await FindingRepo.from_mongo(mongo).upsert_many(findings)

    fresh_hosts = js_miner.new_hostnames(
        mined, known={a["hostname"] for a in assets}, own_domains=own_domains
    )
    if fresh_hosts:
        logger.info(
            "js_mine: {} new hostname(s) referenced in JS: {}",
            len(fresh_hosts),
            fresh_hosts[:5],
        )

    logger.info(
        "js_mine: {} file(s) mined → {} endpoints ({} new), {} findings, {} new hosts",
        files_total,
        ep_total,
        ep_new,
        f_total,
        len(fresh_hosts),
    )
    return {
        "files": files_total,
        "new_files": files_new,
        "endpoints": ep_total,
        "new": ep_new,
        "findings": f_total,
        "new_findings": f_new,
        "new_hostnames": len(fresh_hosts),
        # Fed to the cascade so newly-named hosts get resolved + probed.
        "hostnames": fresh_hosts,
    }


def _throttled(fetch, limiter: PolitenessLimiter):
    async def _f(url: str) -> str:
        await limiter.acquire(urlsplit(url).hostname or url)
        return await fetch(url)

    return _f


async def _default_fetch(url: str) -> str:  # pragma: no cover - real network
    """Fetch a JS bundle through the SSRF-safe guarded session."""
    import aiohttp

    from modules.safe_http import assert_url_allowed, guarded_session

    assert_url_allowed(url)
    async with guarded_session() as session:
        async with session.get(
            url, timeout=aiohttp.ClientTimeout(total=25), ssl=False, allow_redirects=False
        ) as resp:
            if resp.status != 200:
                return ""
            raw = await resp.content.read(MAX_BYTES)
            return raw.decode("utf-8", errors="ignore")
