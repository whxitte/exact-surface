"""Parameter-discovery stage.

Two halves with very different costs, so they are reported separately:

* the **observed inventory** — parameters already present in URLs we hold, which costs
  no requests and usually accounts for most of the real surface;
* the **candidate probe** — a bounded binary search over a curated parameter list,
  which costs requests and so is opt-in.

The probe compares responses; it never submits a hostile value. The batch-then-split
strategy is what makes it affordable: one request eliminates a dozen names at a time,
so a URL costs roughly log(n) requests rather than n.
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
from modules.scanning import params as P
from modules.scanning.arjun import find_params as arjun_find

CONCURRENCY = 4


async def run_param_discovery(
    *,
    mongo: Any,
    engine: ScopeEngine,
    scope: ProgramScope,
    tenant: TenantContext,
    program_id: str,
    timeout: float = 20.0,
    limiter: PolitenessLimiter | None = None,
    fetch=None,
    arjun=None,
) -> dict:
    fetch = fetch or _default_fetch
    arjun = arjun or arjun_find
    if limiter is not None:
        fetch = _throttled(fetch, limiter)

    ep_repo = EndpointRepo.from_mongo(mongo)
    endpoints = await ep_repo.list(tenant.tenant_id, program_id, limit=100_000)
    all_urls = [ep.get("url") or "" for ep in endpoints]

    # -- half 1: the free inventory -------------------------------------------------
    observed = P.extract_observed(all_urls)
    logger.info("param_discovery: {} parameter(s) already visible in known URLs", len(observed))

    findings: list[Finding] = []
    for obs in observed:
        notable = obs.notable
        if not notable:
            continue
        severity, what = notable
        findings.append(
            Finding(
                tenant_id=tenant.tenant_id,
                program_id=program_id,
                fingerprint=finding_fingerprint(program_id, "param-observed", obs.name),
                check_id="sensitive-parameter-in-use",
                module="param_discovery",
                location=obs.example_url,
                locator=obs.name,
                name=f"Application uses {what}: ?{obs.name}=",
                description=(
                    f"The parameter '{obs.name}' appears in URLs this site publishes, and it "
                    f"is {what}. That is worth a look because parameters of this kind change "
                    "what the application does or shows, and they are frequently reachable "
                    "by anyone who guesses the value. No value was submitted — this is an "
                    "inventory of what your own pages already expose."
                ),
                severity=severity,
                reproduction=f"curl -s '{obs.example_url}'",
                raw={"parameter": obs.name, "values_seen": obs.values_seen},
            )
        )

    # -- half 2: the bounded probe --------------------------------------------------
    assets = await AssetRepo.from_mongo(mongo).list(tenant.tenant_id, program_id, limit=100_000)
    ips_by_host = {a["hostname"]: a.get("resolved_ips", []) for a in assets}

    targets: list[str] = []
    seen_paths: set[str] = set()
    for ep in endpoints:
        url = ep.get("url") or ""
        parts = urlsplit(url)
        host = parts.hostname or ""
        if not parts.scheme or not host or not scope.owns_host(host):
            continue
        if ep.get("status_code") not in (200, 302, 301, None):
            continue
        if not engine.evaluate(host, ips_by_host.get(host, []), scope).permits(Action.HTTP_PROBE):
            continue
        key = f"{host}{parts.path}"
        if key in seen_paths:
            continue  # one probe per distinct path; query variants add nothing here
        seen_paths.add(key)
        targets.append(url)
        if len(targets) >= P.MAX_URLS:
            break

    hidden: list[P.HiddenParam] = []
    probes = 0
    by_arjun: dict[str, list[str]] = {}

    if not targets:
        logger.info("param_discovery: no probeable endpoints yet")
    else:
        # arjun is the primary engine — a maintained wordlist and a smarter stability
        # check than we would write. It degrades to {} when not installed, and the
        # built-in probe below then carries the stage rather than it silently finding
        # nothing. Both run: they disagree often enough to be worth the overlap.
        try:
            by_arjun = await arjun(targets, timeout)
            found = sum(len(v) for v in by_arjun.values())
            logger.info(
                "param_discovery: arjun found {} parameter(s) across {} URL(s)",
                found,
                len(by_arjun),
            )
        except Exception as exc:  # noqa: BLE001 - never let one engine sink the stage
            logger.warning("param_discovery: arjun engine failed ({}); using built-in probe", exc)

        logger.info("param_discovery: probing {} URL(s) for hidden parameters", len(targets))
        sem = asyncio.Semaphore(CONCURRENCY)

        async def probe(url: str) -> None:
            nonlocal probes
            async with sem:
                try:
                    status, body = await fetch(url)
                    probes += 1
                except Exception as exc:  # noqa: BLE001 - one URL never sinks the stage
                    logger.debug("param_discovery: baseline failed for {}: {}", url, exc)
                    return
                baseline = P.Baseline(url=url, status=status, length=len(body))

                # Batch, then split only the batches that moved. A batch that changes
                # nothing eliminates every name in it for one request.
                queue: list[list[str]] = [
                    list(P.CANDIDATE_PARAMS[i : i + P.BATCH])
                    for i in range(0, len(P.CANDIDATE_PARAMS), P.BATCH)
                ]
                while queue:
                    batch = queue.pop()
                    try:
                        status, body = await fetch(P.probe_url(url, batch))
                        probes += 1
                    except Exception:  # noqa: BLE001, S112 - a failed probe just
                        continue  # leaves that batch unresolved; the rest still run
                    if not P.analyse_batch(baseline, batch, status, body):
                        continue
                    if len(batch) == 1:
                        hit = P.classify(batch[0], baseline, status, body)
                        if hit:
                            logger.info(
                                "param_discovery: hidden ?{}= on {} ({})",
                                hit.name,
                                url,
                                hit.severity.value,
                            )
                            hidden.append(hit)
                        continue
                    mid = len(batch) // 2
                    queue.extend([batch[:mid], batch[mid:]])

        await asyncio.gather(*(probe(u) for u in targets), return_exceptions=True)

    # Fold arjun's hits in, skipping anything the built-in probe already reported so a
    # parameter both engines agree on is one finding, not two.
    already = {(h.url, h.name) for h in hidden}
    for url, names in by_arjun.items():
        for name in names:
            if (url, name) in already:
                continue
            already.add((url, name))
            severity, what = P.classify_name(name)
            hidden.append(
                P.HiddenParam(
                    name=name,
                    url=url,
                    severity=severity,
                    evidence=(
                        f"arjun identified '{name}' as {what} accepted by this URL: adding it "
                        "changed the response in a way a stable baseline rules out as noise. "
                        "It is not linked or documented anywhere we crawled. Only the "
                        "parameter's existence was tested; no hostile value was submitted."
                    ),
                )
            )

    for hit in hidden:
        findings.append(
            Finding(
                tenant_id=tenant.tenant_id,
                program_id=program_id,
                fingerprint=finding_fingerprint(program_id, f"param-{hit.name}", hit.url),
                check_id=hit.check_id,
                module="param_discovery",
                location=hit.url,
                locator=hit.name,
                name=f"Undocumented parameter accepted: ?{hit.name}=",
                description=hit.evidence,
                severity=hit.severity,
                reproduction=f"curl -s '{P.probe_url(hit.url, [hit.name])}'",
                raw={"parameter": hit.name, "reflected": hit.reflected},
            )
        )

    total, new = await FindingRepo.from_mongo(mongo).upsert_many(findings)
    logger.info(
        "param_discovery: {} observed, {} hidden found in {} request(s) ({} new finding(s))",
        len(observed),
        len(hidden),
        probes,
        new,
    )
    return {
        "observed": len(observed),
        "probed_urls": len(targets),
        "requests": probes,
        "hidden": len(hidden),
        "by_arjun": sum(len(v) for v in by_arjun.values()),
        "findings": total,
        "new": new,
    }


def _throttled(fn, limiter: PolitenessLimiter):
    async def _f(url: str):
        await limiter.acquire(urlsplit(url).hostname or url)
        return await fn(url)

    return _f


async def _default_fetch(url: str):  # pragma: no cover - real network
    import aiohttp

    from modules.safe_http import assert_url_allowed, guarded_session

    assert_url_allowed(url)
    async with guarded_session() as session:
        async with session.get(
            url, timeout=aiohttp.ClientTimeout(total=15), ssl=False, allow_redirects=False
        ) as resp:
            return resp.status, (await resp.text(errors="ignore"))[:400_000]
