"""Secret-scan pipeline — endpoints → exposed secrets (module 8, §9c).

Fetches scope-permitted endpoint bodies, detects secrets, and stores each as an
ExposedSecret carrying only a MASKED value + a keyed hash + a locator — never the
plaintext (ADR-0006). Alerts (Phase F) likewise carry the masked value only.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from core.config import get_settings
from core.hashing import keyed_hash, secret_fingerprint
from core.logging import logger
from core.models import ExposedSecret
from core.scope import Action, ProgramScope, ScopeEngine
from core.secrets_policy import mask
from core.tenant import TenantContext
from db.assets import AssetRepo
from db.endpoints import EndpointRepo
from db.secrets import SecretRepo
from modules.scanning.secretfinder import _default_fetch, scan_urls


async def run_secret_scan(
    *,
    mongo: Any,
    engine: ScopeEngine,
    scope: ProgramScope,
    tenant: TenantContext,
    program_id: str,
    hmac_key: bytes | None = None,
    fetch=_default_fetch,
) -> dict:
    hmac_key = hmac_key or get_settings().secret_hash_key_bytes()
    tid = tenant.tenant_id

    assets = await AssetRepo.from_mongo(mongo).list(tid, program_id, limit=100_000)
    ips_by_host = {a["hostname"]: a.get("resolved_ips", []) for a in assets}
    endpoints = await EndpointRepo.from_mongo(mongo).list(tid, program_id, limit=100_000)

    targets: list[str] = []
    for ep in endpoints:
        host = urlsplit(ep["url"]).hostname or ""
        if engine.evaluate(host, ips_by_host.get(host, []), scope).permits(Action.HTTP_PROBE):
            targets.append(ep["url"])

    if not targets:
        logger.info("secret scan {}: nothing to scan (no endpoints yet)", program_id)
        return {
            "scanned": 0, "secrets": 0, "new": 0, "new_secrets": [],
            "skipped": True, "note": "no endpoints to scan yet — probe/crawl first",
        }

    logger.info("secret-scanning {} endpoint(s)", len(targets))
    hits = await scan_urls(targets, fetch=fetch)
    models = [
        ExposedSecret(
            tenant_id=tid,
            program_id=program_id,
            fingerprint=secret_fingerprint(program_id, h["value"], h["source_locator"], hmac_key),
            kind=h["kind"],
            masked=mask(h["value"]),
            value_hash=keyed_hash(h["value"], hmac_key),
            source_locator=h["source_locator"],
            severity=h["severity"],
        )
        for h in hits
    ]
    res = await SecretRepo.from_mongo(mongo).upsert_all(models)
    new = [
        {"kind": m.kind, "masked": m.masked, "where": m.source_locator}
        for m, x in zip(models, res, strict=True)
        if x.inserted
    ]

    logger.info(
        "secret scan {}: {} urls, {} secrets, {} new",
        program_id,
        len(targets),
        len(models),
        len(new),
    )
    return {"scanned": len(targets), "secrets": len(models), "new": len(new), "new_secrets": new}
