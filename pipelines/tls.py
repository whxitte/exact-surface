"""TLS inspection pipeline (module 6, optional) — tlsx over in-scope hosts.

Inspects certificate chains on hosts that permit TLS inspection and records an
expired certificate as a Finding (a real, low-effort exposure). Optional: runs
only when the ``tls`` module is enabled for the program.
"""

from __future__ import annotations

from typing import Any

from core.hashing import finding_fingerprint
from core.logging import logger
from core.models import Finding
from core.scope import Action, ProgramScope, ScopeEngine
from core.severity import Severity
from core.tenant import TenantContext
from db.assets import AssetRepo
from db.findings import FindingRepo
from modules.probing.tlsx import inspect as tlsx_inspect


async def run_tls_scan(
    *,
    mongo: Any,
    engine: ScopeEngine,
    scope: ProgramScope,
    tenant: TenantContext,
    program_id: str,
    timeout: float,
    tlsinspect=tlsx_inspect,
) -> dict:
    assets = await AssetRepo.from_mongo(mongo).list(tenant.tenant_id, program_id, limit=100_000)
    hosts = [
        a["hostname"]
        for a in assets
        if engine.evaluate(a["hostname"], a.get("resolved_ips", []), scope).permits(
            Action.TLS_INSPECT
        )
    ]
    if not hosts:
        return {
            "inspected": 0, "expired": 0, "new": 0,
            "skipped": True, "note": "no TLS-probeable hosts yet",
        }

    logger.info("tls: inspecting certs on {} host(s) with tlsx", len(hosts))
    certs = await tlsinspect(hosts, timeout)
    models = [
        Finding(
            tenant_id=tenant.tenant_id,
            program_id=program_id,
            fingerprint=finding_fingerprint(program_id, "ssl-expired", c["host"]),
            check_id="ssl-expired",
            module="tlsx",
            location=c["host"],
            name="Expired TLS certificate",
            description=f"Certificate for {c.get('cn') or c['host']} is expired.",
            severity=Severity.MEDIUM,
        )
        for c in certs
        if c.get("expired")
    ]
    _, new = await FindingRepo.from_mongo(mongo).upsert_many(models)
    logger.info("tls: {} cert(s) inspected, {} expired, {} new", len(certs), len(models), new)
    return {"inspected": len(certs), "expired": len(models), "new": new}
