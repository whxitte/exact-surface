"""GitHub OSINT pipeline — leaked secrets → Leak records (masked, §9c)."""

from __future__ import annotations

from typing import Any

from core.config import get_settings
from core.hashing import keyed_hash, secret_fingerprint
from core.logging import logger
from core.models import Leak
from core.secrets_policy import mask
from core.tenant import TenantContext
from db.leaks import LeakRepo
from modules.osint.github import search_leaks


async def run_github_leak_scan(
    *,
    mongo: Any,
    tenant: TenantContext,
    program_id: str,
    domain: str,
    hmac_key: bytes | None = None,
    search=None,
) -> dict:
    hmac_key = hmac_key or get_settings().secret_hash_key_bytes()
    kwargs = {"search": search} if search is not None else {}
    hits = await search_leaks(domain, **kwargs)

    models = [
        Leak(
            tenant_id=tenant.tenant_id,
            program_id=program_id,
            fingerprint=secret_fingerprint(program_id, h["value"], h.get("url", ""), hmac_key),
            kind=h["kind"],
            masked=mask(h["value"]),
            value_hash=keyed_hash(h["value"], hmac_key),
            source="github",
            repo=h.get("repo"),
            file_path=h.get("file_path"),
            url=h.get("url"),
            severity=h["severity"],
        )
        for h in hits
    ]
    res = await LeakRepo.from_mongo(mongo).upsert_all(models)
    new = [
        {"kind": m.kind, "masked": m.masked, "repo": m.repo}
        for m, x in zip(models, res, strict=True)
        if x.inserted
    ]
    logger.info("github-osint {}: {} hits, {} new", domain, len(models), len(new))
    return {"hits": len(models), "new": len(new), "new_leaks": new}
