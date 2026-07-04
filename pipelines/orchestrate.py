"""Full-pipeline orchestration: ingest → probe → scan for one program.

This is what a worker runs for a program. It (1) refuses to proceed without a
current authorization record (§9b/§9e), (2) builds the ``ProgramScope`` from the
program + authorization, (3) runs the three pipelines in order, and (4) records a
``ScanRun`` audit row with per-stage stats.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from core.errors import AuthorizationRequired
from core.logging import bind_context, logger
from core.models import ScanRun, ScanStatus
from core.scope import ProgramScope, ScopeEngine
from core.tenant import TenantContext
from db.audit import ScanRunRepo
from db.authorizations import AuthorizationRepo
from db.programs import ProgramRepo
from pipelines.ingest import run_ingest
from pipelines.probe import run_probe
from pipelines.scan import run_scan


def build_program_scope(program: dict, authorization: dict | None) -> ProgramScope:
    """Assemble the immutable scope object the engine evaluates against."""
    dedicated: tuple[str, ...] = ()
    if authorization:
        dedicated = tuple(
            e["cidr"]
            for e in authorization.get("ip_scope", [])
            if e.get("ip_class") == "dedicated"
        )
    return ProgramScope(
        verified_apexes=(program["apex_domain"],),
        excluded_hosts=frozenset(program.get("excluded_hosts", [])),
        excluded_cidrs=tuple(program.get("excluded_cidrs", [])),
        authorized_dedicated_cidrs=dedicated,
    )


def _auth_is_current(auth: dict | None) -> bool:
    return bool(auth and auth.get("apex_verified") and not auth.get("revoked"))


async def run_full_pipeline(
    *,
    mongo: Any,
    engine: ScopeEngine,
    scope: ProgramScope,
    tenant: TenantContext,
    program_id: str,
    apex: str,
    timeout: float,
    **injected: Any,
) -> dict:
    """Run all three pipelines. ``injected`` forwards test doubles per stage:
    ``subfinder``, ``crtsh``, ``resolve`` (ingest); ``probe``; ``scan``."""
    scan_id = uuid.uuid4().hex
    audit = ScanRunRepo.from_mongo(mongo)
    run = ScanRun(
        tenant_id=tenant.tenant_id, scan_id=scan_id, program_id=program_id,
        pipeline="full", status=ScanStatus.RUNNING, started_at=datetime.now(UTC),
    )
    await audit.save(run)

    with bind_context(tenant.tenant_id, scan_id):
        try:
            ingest_kw = {k: injected[k] for k in ("subfinder", "crtsh", "resolve") if k in injected}
            ingest = await run_ingest(
                mongo=mongo, engine=engine, scope=scope, tenant=tenant,
                program_id=program_id, apex=apex, timeout=timeout, **ingest_kw,
            )
            probe_kw = {"probe": injected["probe"]} if "probe" in injected else {}
            probe = await run_probe(
                mongo=mongo, engine=engine, scope=scope, tenant=tenant,
                program_id=program_id, timeout=timeout, **probe_kw,
            )
            scan_kw = {"scan": injected["scan"]} if "scan" in injected else {}
            scan = await run_scan(
                mongo=mongo, engine=engine, scope=scope, tenant=tenant,
                program_id=program_id, timeout=timeout, **scan_kw,
            )
        except Exception as exc:
            run.status = ScanStatus.FAILED
            run.finished_at = datetime.now(UTC)
            run.error = f"{type(exc).__name__}: {exc}"
            await audit.save(run)
            logger.error("pipeline failed for {}: {}", program_id, exc)
            raise

        stats = {"ingest": ingest, "probe": probe, "scan": scan}
        run.status = ScanStatus.SUCCESS
        run.finished_at = datetime.now(UTC)
        run.stats = {
            "assets_new": ingest["new"],
            "endpoints_new": probe["new"],
            "findings_new": scan["new"],
        }
        await audit.save(run)
        return {"scan_id": scan_id, **stats}


async def run_program(
    *,
    mongo: Any,
    engine: ScopeEngine,
    tenant: TenantContext,
    program_id: str,
    timeout: float,
) -> dict:
    """Load program + authorization, enforce authorization, then run the pipeline."""
    program = await ProgramRepo.from_mongo(mongo).get(tenant.tenant_id, program_id)
    if not program:
        raise AuthorizationRequired(f"no program {program_id} for tenant {tenant.tenant_id}")

    auth = await AuthorizationRepo.from_mongo(mongo).get(tenant.tenant_id, program_id)
    if not _auth_is_current(auth):
        raise AuthorizationRequired(
            f"no current authorization for program {program_id}; refusing to scan"
        )

    scope = build_program_scope(program, auth)
    return await run_full_pipeline(
        mongo=mongo, engine=engine, scope=scope, tenant=tenant,
        program_id=program_id, apex=program["apex_domain"], timeout=timeout,
    )
