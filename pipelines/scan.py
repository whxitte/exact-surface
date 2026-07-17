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

from core.config import get_settings
from core.hashing import finding_fingerprint
from core.logging import logger
from core.models import Finding
from core.ratelimit import derive_subprocess_rate
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
    targets: set[str] | None = None,
    scan=nuclei_scan,
) -> dict:
    tid = tenant.tenant_id
    assets = await AssetRepo.from_mongo(mongo).list(tid, program_id, limit=100_000)
    ips_by_host = {a["hostname"]: a.get("resolved_ips", []) for a in assets}
    endpoints = await EndpointRepo.from_mongo(mongo).list(tid, program_id, limit=100_000)

    # ONE representative URL per host, not every crawled endpoint. nuclei's templates
    # carry their own paths (they append /admin, /.env, … to the base URL themselves),
    # so feeding all N endpoints of a host just re-runs the same template set against
    # the same host N times — massively slower for no extra coverage. Scanning the
    # host root gives full per-subdomain coverage. (Prefer an https endpoint's scheme.)
    scheme_by_host: dict[str, str] = {}
    for ep in endpoints:
        parts = urlsplit(ep["url"])
        host = parts.hostname or ""
        if not host or (targets and host not in targets):
            continue
        if host not in scheme_by_host or parts.scheme == "https":
            scheme_by_host[host] = parts.scheme or "https"

    safe_urls: list[str] = []
    aggressive_urls: list[str] = []
    for host, scheme in scheme_by_host.items():
        decision = engine.evaluate(host, ips_by_host.get(host, []), scope)
        if not decision.permits(Action.HTTP_PROBE):
            continue
        url = f"{scheme}://{host}"
        (aggressive_urls if decision.permits(Action.ACTIVE_SCAN) else safe_urls).append(url)

    if not safe_urls and not aggressive_urls:
        logger.info("scan {}: nothing to scan (no endpoints yet)", program_id)
        return {
            "scanned_safe": 0,
            "scanned_aggressive": 0,
            "findings": 0,
            "new": 0,
            "new_findings": [],
            "skipped": True,
            "note": "no endpoints to scan yet — probe/crawl first",
        }

    # nuclei runs the full template set over every URL — slow. The caller sizes the
    # budget via the configurable per-phase "scan" timeout (default 60m); nuclei
    # streams findings and keeps partial results at this budget, so it bounds the run.
    nuclei_timeout = timeout
    logger.info(
        "scanning {} safe + {} aggressive url(s) with nuclei (timeout {:.0f}s)",
        len(safe_urls),
        len(aggressive_urls),
        nuclei_timeout,
    )
    findings_repo = FindingRepo.from_mongo(mongo)

    def _fp(f: dict) -> str:
        return finding_fingerprint(program_id, f["template_id"], f["matched_at"])

    def _model(f: dict) -> Finding:
        return Finding(
            tenant_id=tenant.tenant_id,
            program_id=program_id,
            fingerprint=_fp(f),
            check_id=f["template_id"],
            module="nuclei",
            location=f["matched_at"],
            locator=f.get("matched", ""),  # e.g. the detected tech names
            name=f["name"] or f["template_id"],
            description=f["description"],
            severity=_severity(f["severity"]),
            references=f.get("reference") or [],
            raw=f.get("raw") or {},
        )

    # Real-time persistence: write each finding to the DB the instant nuclei emits it,
    # so it shows in the UI immediately instead of only after the whole batch. New
    # ones are tracked here (so the notify cascade still fires) and their fingerprints
    # recorded so the end-of-run upsert doesn't re-process them.
    streamed_fps: set[str] = set()
    new_findings: list[dict] = []

    async def on_finding(f: dict) -> None:
        model = _model(f)
        result = await findings_repo.upsert(model)
        streamed_fps.add(model.fingerprint)
        if result.inserted:
            new_findings.append(
                {"name": model.name, "severity": model.severity.value, "location": model.location}
            )

    # §3.8b: nuclei is a subprocess, so -rl is the only ceiling that reaches it (its
    # own default is 150 rps). The lists above hold ONE url per host, so their length
    # IS the host count and the aggregate math holds — if that ever changes to
    # multiple urls per host, this silently grants that host N x the cap (ADR-0013).
    cap = get_settings().global_rate_per_target
    raw: list[dict] = []
    if safe_urls:
        rate = derive_subprocess_rate(len(safe_urls), cap, tool="nuclei")
        raw += await scan(
            safe_urls, nuclei_timeout, aggressive=False, rate=rate.aggregate, on_finding=on_finding
        )
    if aggressive_urls:
        rate = derive_subprocess_rate(len(aggressive_urls), cap, tool="nuclei")
        raw += await scan(
            aggressive_urls,
            nuclei_timeout,
            aggressive=True,
            rate=rate.aggregate,
            on_finding=on_finding,
        )

    # Persist anything NOT already streamed (e.g. an injected runner in tests, or a
    # finding whose real-time write failed) — idempotent, so nothing is double-counted.
    leftover = [_model(f) for f in raw if _fp(f) not in streamed_fps]
    if leftover:
        res = await findings_repo.upsert_all(leftover)
        new_findings += [
            {"name": m.name, "severity": m.severity.value, "location": m.location}
            for m, x in zip(leftover, res, strict=True)
            if x.inserted
        ]

    logger.info(
        "scan {}: {} safe + {} aggressive urls, {} findings, {} new",
        program_id,
        len(safe_urls),
        len(aggressive_urls),
        len(raw),
        len(new_findings),
    )
    return {
        "scanned_safe": len(safe_urls),
        "scanned_aggressive": len(aggressive_urls),
        "findings": len(raw),
        "new": len(new_findings),
        "new_findings": new_findings,
    }
