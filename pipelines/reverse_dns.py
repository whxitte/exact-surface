"""Reverse-DNS stage — PTR sweep of ranges confirmed dedicated to the operator.

The only stage whose input is a CIDR rather than a name, which makes it the one with
the most room to go wrong. Two things keep it safe:

* it reads ``scope.authorized_dedicated_cidrs``, which is populated only by the §9b
  ASN/WHOIS confirmation path — never by an operator typing a range into a form;
* :func:`modules.recon.reverse_dns.expand` refuses anything wider than a /20, so an
  over-broad entry produces nothing rather than thousands of lookups.

Discovered in-scope names become assets, so they flow into probing and everything
downstream on the next run. Out-of-scope names are logged and counted but never stored:
a PTR that resolves to somebody else's domain is not our asset, whatever range it sits
in, and persisting it would violate §9b's rule against out-of-scope data.
"""

from __future__ import annotations

from typing import Any

from core.hashing import asset_fingerprint
from core.logging import logger
from core.models import Asset
from core.scope import ProgramScope
from core.tenant import TenantContext
from db.assets import AssetRepo
from modules.recon import reverse_dns as rdns


async def run_reverse_dns(
    *,
    mongo: Any,
    scope: ProgramScope,
    tenant: TenantContext,
    program_id: str,
    timeout: float = 120.0,
    lookup=None,
) -> dict:
    """PTR-sweep every authorised dedicated range and keep the in-scope names."""
    lookup = lookup or _default_lookup

    cidrs = list(scope.authorized_dedicated_cidrs or ())
    if not cidrs:
        logger.info("reverse_dns: no ASN-confirmed dedicated ranges — nothing to sweep")
        return {
            "skipped": True,
            "note": (
                "no confirmed-dedicated IP ranges. This stage only sweeps ranges the "
                "authorization step verified you own, so there is nothing it may scan."
            ),
        }

    ips = rdns.expand_all(cidrs)
    if not ips:
        logger.warning(
            "reverse_dns: {} range(s) present but none are sweepable "
            "(ranges wider than /20 are refused): {}",
            len(cidrs),
            ", ".join(cidrs[:5]),
        )
        return {
            "skipped": True,
            "note": "authorized ranges are wider than /20; refusing to expand them",
        }

    logger.info("reverse_dns: sweeping {} address(es) across {} range(s)", len(ips), len(cidrs))
    try:
        answers = await lookup(ips, timeout)
    except Exception as exc:  # noqa: BLE001 - DNS trouble is not a stage failure
        logger.warning("reverse_dns: PTR lookup failed ({})", exc)
        return {"skipped": True, "note": f"PTR lookup unavailable: {exc}"}

    own = tuple(scope.verified_apexes)
    in_scope: list[rdns.ReverseHit] = []
    foreign = 0
    for ip, hostname in sorted(answers.items()):
        hit = rdns.classify(ip, hostname, own)
        if hit is None:
            continue
        if hit.in_scope:
            logger.info("reverse_dns: {} → {} (in scope, new surface)", ip, hit.hostname)
            in_scope.append(hit)
        else:
            # Counted so the user can see the sweep worked, never stored: a name outside
            # our scope is not ours to keep, whatever range it sits in.
            foreign += 1
            logger.debug("reverse_dns: {} → {} (out of scope, not stored)", ip, hit.hostname)

    assets = [
        Asset(
            tenant_id=tenant.tenant_id,
            program_id=program_id,
            fingerprint=asset_fingerprint(program_id, hit.hostname),
            hostname=hit.hostname,
            resolved_ips=[hit.ip],
            source="reverse_dns",
        )
        for hit in in_scope
    ]
    total, new = await AssetRepo.from_mongo(mongo).upsert_many(assets)
    logger.info(
        "reverse_dns: {} address(es) swept → {} in-scope host(s) ({} new), "
        "{} out-of-scope name(s) ignored",
        len(ips),
        len(in_scope),
        new,
        foreign,
    )
    return {
        "swept": len(ips),
        "ranges": len(cidrs),
        "discovered": len(in_scope),
        "out_of_scope": foreign,
        "assets": total,
        "new": new,
        "cascade_targets": [h.hostname for h in in_scope],
    }


async def _default_lookup(ips: list[str], timeout: float):  # pragma: no cover - real DNS
    from modules.recon.dnsx import resolve_ptr

    return await resolve_ptr(ips, timeout)
