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
    targets: set[str] | None = None,
    fetch=_default_fetch,
) -> dict:
    hmac_key = hmac_key or get_settings().secret_hash_key_bytes()
    tid = tenant.tenant_id

    assets = await AssetRepo.from_mongo(mongo).list(tid, program_id, limit=100_000)
    ips_by_host = {a["hostname"]: a.get("resolved_ips", []) for a in assets}
    endpoints = await EndpointRepo.from_mongo(mongo).list(tid, program_id, limit=100_000)

    urls: list[str] = []
    for ep in endpoints:
        host = urlsplit(ep["url"]).hostname or ""
        if targets and host not in targets:  # cascade: only scan the new hosts
            continue
        if engine.evaluate(host, ips_by_host.get(host, []), scope).permits(Action.HTTP_PROBE):
            urls.append(ep["url"])

    if not urls:
        logger.info("secret scan {}: nothing to scan (no endpoints yet)", program_id)
        return {
            "scanned": 0,
            "secrets": 0,
            "new": 0,
            "new_secrets": [],
            "skipped": True,
            "note": "no endpoints to scan yet — probe/crawl first",
        }

    logger.info("secret-scanning {} endpoint(s)", len(urls))
    repo = SecretRepo.from_mongo(mongo)

    def _model(h: dict) -> ExposedSecret:
        return ExposedSecret(
            tenant_id=tid,
            program_id=program_id,
            fingerprint=secret_fingerprint(program_id, h["value"], h["source_locator"], hmac_key),
            kind=h["kind"],
            masked=mask(h["value"]),
            value_hash=keyed_hash(h["value"], hmac_key),
            source_locator=h["source_locator"],
            severity=h["severity"],
        )

    # Persist each secret the INSTANT it's found — a stage timeout on a huge haul then
    # keeps everything found so far instead of losing the whole batch (real-time UI).
    seen: set[str] = set()
    new: list[dict] = []

    async def _persist(h: dict) -> None:
        m = _model(h)
        if m.fingerprint in seen:
            return
        seen.add(m.fingerprint)
        r = await repo.upsert(m)
        if r.inserted:
            new.append({"kind": m.kind, "masked": m.masked, "where": m.source_locator})

    hits = await scan_urls(urls, fetch=fetch, on_hit=_persist)
    # Backstop: upsert any hit the callback didn't already store (idempotent).
    leftover = [_model(h) for h in hits if _model(h).fingerprint not in seen]
    if leftover:
        res = await repo.upsert_all(leftover)
        for m, x in zip(leftover, res, strict=True):
            seen.add(m.fingerprint)
            if x.inserted:
                new.append({"kind": m.kind, "masked": m.masked, "where": m.source_locator})

    logger.info(
        "secret scan {}: {} urls, {} secrets, {} new",
        program_id,
        len(urls),
        len(seen),
        len(new),
    )
    return {"scanned": len(urls), "secrets": len(seen), "new": len(new), "new_secrets": new}
