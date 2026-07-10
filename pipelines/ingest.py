"""Ingest pipeline — recon → assets (modules 1,2,4).

Runs passive subdomain sources (subfinder + crt.sh), keeps only hosts under a
verified apex, resolves them (dnsx), classifies each resolved IP, flags ephemeral
preview/staging envs, and idempotently upserts Assets. Returns which hosts are
genuinely new so the caller can alert.

Wrapper callables are injected (defaulting to the real tools) so the whole
pipeline is unit-testable with canned data and no network.
"""

from __future__ import annotations

from typing import Any

from core.fingerprint import is_ephemeral_host
from core.hashing import asset_fingerprint
from core.logging import logger
from core.models import Asset
from core.scope import ProgramScope, ScopeEngine
from core.tenant import TenantContext
from db.assets import AssetRepo
from modules.recon.crtsh import enumerate_subdomains as crtsh_enum
from modules.recon.dnsx import recon_hosts as dnsx_recon
from modules.recon.dnsx import resolve_hosts as dnsx_resolve
from modules.recon.subfinder import enumerate_subdomains as subfinder_enum


async def run_ingest(
    *,
    mongo: Any,
    engine: ScopeEngine,
    scope: ProgramScope,
    tenant: TenantContext,
    program_id: str,
    apex: str,
    timeout: float,
    subfinder=subfinder_enum,
    crtsh=crtsh_enum,
    resolve=dnsx_resolve,
    dns_recon=dnsx_recon,
) -> dict:
    logger.info("discovering subdomains of {} (subfinder + crt.sh)", apex)
    subs = await subfinder(apex, timeout)
    crt = await crtsh(apex)
    candidates = sorted(set(subs) | set(crt) | {apex.lower().rstrip(".")})
    logger.info(
        "found {} candidate(s) ({} subfinder, {} crt.sh); resolving with dnsx",
        len(candidates),
        len(subs),
        len(crt),
    )

    # Scope gate: never persist a host outside a verified apex.
    in_scope = [h for h in candidates if scope.owns_host(h)]
    resolved = await resolve(in_scope, timeout)
    logger.info("dnsx resolved {}/{} in-scope host(s) to live IPs", len(resolved), len(in_scope))

    # Full DNS records per host (CNAME/NS/MX/TXT + A/AAAA) — best-effort enrichment.
    dns = await dns_recon(in_scope, timeout)
    if dns:
        logger.info("dnsx recon: {} host(s) enriched with full DNS records", len(dns))

    models = [
        Asset(
            tenant_id=tenant.tenant_id,
            program_id=program_id,
            fingerprint=asset_fingerprint(program_id, host),
            hostname=host,
            resolved_ips=resolved.get(host, []),
            ip_class=(engine.classify_ip(resolved[host][0]).value if resolved.get(host) else None),
            source="ingest",
            is_ephemeral=is_ephemeral_host(host),
            dns_records=dns.get(host, {}),
        )
        for host in in_scope
    ]
    results = await AssetRepo.from_mongo(mongo).upsert_all(models)
    new_hosts = [m.hostname for m, r in zip(models, results, strict=True) if r.inserted]

    logger.info(
        "ingest complete for {}: {} candidates → {} in-scope assets, {} new",
        apex,
        len(candidates),
        len(in_scope),
        len(new_hosts),
    )
    return {
        "candidates": len(candidates),
        "in_scope": len(in_scope),
        "discovered": len(models),
        "new": len(new_hosts),
        "new_hosts": new_hosts,
        # cascade: probe the newly discovered hosts immediately (event-driven path)
        "cascade_targets": new_hosts,
    }
