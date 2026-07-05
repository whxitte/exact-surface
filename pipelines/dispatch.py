"""Pipeline dispatch — run one named pipeline for a program (auth-gated).

The worker calls this for each scheduled job. It loads the program + authorization,
refuses without a current authorization (§9b/§9e), builds the ``ProgramScope``, and
routes to the right pipeline. Centralising the routing keeps the worker thin and
the scope/auth enforcement in one place.
"""

from __future__ import annotations

from typing import Any

from core.errors import AuthorizationRequired
from core.scope import ScopeEngine
from core.tenant import TenantContext
from db.authorizations import AuthorizationRepo
from db.programs import ProgramRepo
from pipelines.content_discovery import run_content_discovery
from pipelines.crawl import run_crawl
from pipelines.cve_watch import run_cve_watch
from pipelines.github_osint import run_github_leak_scan
from pipelines.ingest import run_ingest
from pipelines.notify import run_notify
from pipelines.orchestrate import build_program_scope
from pipelines.port_scan import run_port_scan
from pipelines.probe import run_probe
from pipelines.scan import run_scan
from pipelines.secrets import run_secret_scan


def _auth_current(auth: dict | None) -> bool:
    return bool(auth and auth.get("apex_verified") and not auth.get("revoked"))


async def run_pipeline(
    *,
    mongo: Any,
    engine: ScopeEngine,
    tenant: TenantContext,
    program_id: str,
    pipeline: str,
    timeout: float,
    hmac_key: bytes | None = None,
) -> dict:
    program = await ProgramRepo.from_mongo(mongo).get(tenant.tenant_id, program_id)
    if not program:
        raise AuthorizationRequired(f"no program {program_id} for tenant {tenant.tenant_id}")
    auth = await AuthorizationRepo.from_mongo(mongo).get(tenant.tenant_id, program_id)
    if not _auth_current(auth):
        raise AuthorizationRequired(f"no current authorization for program {program_id}")

    scope = build_program_scope(program, auth)
    apex = program["apex_domain"]
    common = dict(
        mongo=mongo,
        engine=engine,
        scope=scope,
        tenant=tenant,
        program_id=program_id,
        timeout=timeout,
    )

    async def _execute() -> dict:
        if pipeline == "ingest":
            return await run_ingest(**common, apex=apex)
        if pipeline == "probe":
            return await run_probe(**common)
        if pipeline == "crawl":
            return await run_crawl(**common, apex=apex)
        if pipeline == "scan":
            return await run_scan(**common)
        if pipeline == "content_discovery":
            return await run_content_discovery(**common)
        if pipeline == "port_scan":
            return await run_port_scan(**common)
        if pipeline == "secrets":
            return await run_secret_scan(
                mongo=mongo, engine=engine, scope=scope, tenant=tenant,
                program_id=program_id, hmac_key=hmac_key,
            )
        if pipeline == "cve_watch":
            return await run_cve_watch(mongo=mongo, tenant=tenant, program_id=program_id)
        if pipeline == "github_osint":
            return await run_github_leak_scan(
                mongo=mongo, tenant=tenant, program_id=program_id, domain=apex, hmac_key=hmac_key
            )
        if pipeline == "notify":
            return await run_notify(mongo=mongo, tenant=tenant, program_id=program_id)
        raise ValueError(f"unknown pipeline: {pipeline}")

    # Record a ScanRun so every pipeline execution is visible in the activity feed.
    import uuid
    from datetime import UTC, datetime

    from core.logging import bind_context, logger
    from core.models import ScanRun, ScanStatus
    from db.audit import ScanRunRepo

    audit = ScanRunRepo.from_mongo(mongo)
    run = ScanRun(
        tenant_id=tenant.tenant_id, scan_id=uuid.uuid4().hex, program_id=program_id,
        pipeline=pipeline, status=ScanStatus.RUNNING, started_at=datetime.now(UTC),
    )
    # Attribute every log line from this cadence run (tenant/program/scan/pipeline)
    # — the scheduler path previously logged with no context (t=- s=-).
    with bind_context(
        tenant_id=tenant.tenant_id, scan_id=run.scan_id,
        program_id=program_id, pipeline=pipeline,
    ):
        await audit.save(run)
        logger.info("{} started", pipeline)
        try:
            result = await _execute()
        except Exception as exc:
            run.status = ScanStatus.FAILED
            run.finished_at = datetime.now(UTC)
            run.error = f"{type(exc).__name__}: {exc}"
            await audit.save(run)
            logger.error("{} failed: {}", pipeline, exc)
            raise
        run.finished_at = datetime.now(UTC)
        if result.get("skipped"):
            run.status = ScanStatus.SKIPPED
            run.note = result.get("note")
            logger.info("{} skipped: {}", pipeline, run.note)
        else:
            run.status = ScanStatus.SUCCESS
            run.stats = {k: v for k, v in result.items() if isinstance(v, int)}
        await audit.save(run)
        return result
