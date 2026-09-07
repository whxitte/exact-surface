"""Typosquat stage — registered lookalike domains pointed at the operator.

Generates the mutations phishing operators actually use, resolves them, and reports only
the ones that exist. An unregistered lookalike is not news; a registered one with mail
records is a phishing campaign with the plumbing already installed.

Nothing here touches the operator's infrastructure — it is third-party DNS, the same
lookups anyone can run — and it never contacts the lookalike host itself. Resolution is
batched into two DNS calls rather than one per candidate, because several hundred
sequential lookups would be both slow and rude to resolvers.
"""

from __future__ import annotations

from typing import Any

from core.hashing import finding_fingerprint
from core.logging import logger
from core.models import Finding
from core.tenant import TenantContext
from db.findings import FindingRepo
from modules.osint import typosquat as ts

_REMEDIATION = (
    "You cannot deregister someone else's domain. Practical steps: file a UDRP or "
    "trademark dispute if it infringes your mark, add it to your mail gateway and "
    "phishing blocklists, warn staff who might receive mail from it, and consider "
    "defensively registering the closest variants that are still free."
)


async def run_typosquat(
    *,
    mongo: Any,
    tenant: TenantContext,
    program_id: str,
    apex: str,
    timeout: float = 120.0,
    resolve_many=None,
    resolve_mx_many=None,
) -> dict:
    resolve_many = resolve_many or _default_resolve_many
    resolve_mx_many = resolve_mx_many or _default_mx_many

    candidates = ts.generate(apex)
    if not candidates:
        return {"skipped": True, "note": "no lookalike candidates could be generated"}

    technique_of = dict(candidates)
    names = [d for d, _ in candidates]
    logger.info("typosquat: checking {} lookalike candidate(s) for {}", len(names), apex)

    try:
        resolved = await resolve_many(names, timeout)
    except Exception as exc:  # noqa: BLE001 - DNS trouble must not fail the stage
        logger.warning("typosquat: bulk resolution failed ({}); skipping", exc)
        return {"skipped": True, "note": f"DNS resolution unavailable: {exc}"}

    registered = {d: ips for d, ips in resolved.items() if ips}
    if not registered:
        logger.info("typosquat: none of the {} candidates are registered", len(names))
        return {"candidates": len(names), "registered": 0, "with_mail": 0, "findings": 0, "new": 0}

    try:
        mx_by_domain = await resolve_mx_many(sorted(registered), timeout)
    except Exception:  # noqa: BLE001 - MX is a severity signal, not a requirement
        mx_by_domain = {}

    hits: list[ts.Lookalike] = []
    for domain, ips in sorted(registered.items()):
        has_mx = bool(mx_by_domain.get(domain))
        technique = technique_of.get(domain, "a lookalike mutation")
        logger.info(
            "typosquat: {} is REGISTERED ({}) via {}{}",
            domain,
            ", ".join(ips[:3]),
            technique,
            " [has MX]" if has_mx else "",
        )
        hits.append(ts.Lookalike(domain, technique, tuple(ips[:8]), has_mx))

    findings = [
        Finding(
            tenant_id=tenant.tenant_id,
            program_id=program_id,
            fingerprint=finding_fingerprint(program_id, "typosquat", hit.domain),
            check_id="lookalike-domain-registered",
            module="typosquat",
            location=hit.domain,
            locator=hit.technique,
            name=(
                f"Lookalike domain registered with mail: {hit.domain}"
                if hit.has_mx
                else f"Lookalike domain registered: {hit.domain}"
            ),
            description=hit.evidence,
            severity=hit.severity,
            reproduction=f"dig +short {hit.domain} && dig +short MX {hit.domain}",
            raw={
                "domain": hit.domain,
                "technique": hit.technique,
                "resolved_ips": list(hit.resolved_ips),
                "has_mx": hit.has_mx,
                "remediation": _REMEDIATION,
            },
        )
        for hit in hits
    ]
    total, new = await FindingRepo.from_mongo(mongo).upsert_many(findings)
    with_mail = sum(1 for h in hits if h.has_mx)
    logger.info(
        "typosquat: {}/{} candidate(s) registered, {} with mail ({} new finding(s))",
        len(hits),
        len(names),
        with_mail,
        new,
    )
    return {
        "candidates": len(names),
        "registered": len(hits),
        "with_mail": with_mail,
        "findings": total,
        "new": new,
    }


async def _default_resolve_many(names: list[str], timeout: float):  # pragma: no cover - real DNS
    from modules.recon.dnsx import resolve_hosts

    return await resolve_hosts(names, timeout)


async def _default_mx_many(names: list[str], timeout: float):  # pragma: no cover - real DNS
    from modules.recon.dnsx import resolve_mx_hosts

    return await resolve_mx_hosts(names, timeout)
