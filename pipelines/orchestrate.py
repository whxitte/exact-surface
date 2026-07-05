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
from core.models import ScanRun, ScanStage, ScanStatus
from core.scope import ProgramScope, ScopeEngine
from core.tenant import TenantContext
from db.audit import ScanRunRepo
from db.authorizations import AuthorizationRepo
from db.programs import ProgramRepo
from pipelines.crawl import run_crawl
from pipelines.ingest import run_ingest
from pipelines.probe import run_probe
from pipelines.scan import run_scan
from pipelines.secrets import run_secret_scan


def build_program_scope(program: dict, authorization: dict | None) -> ProgramScope:
    """Assemble the immutable scope object the engine evaluates against."""
    dedicated: tuple[str, ...] = ()
    if authorization:
        dedicated = tuple(
            e["cidr"] for e in authorization.get("ip_scope", []) if e.get("ip_class") == "dedicated"
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
    """Run the full pipeline: ingest → probe → crawl → scan → secrets.

    ``injected`` forwards test doubles per stage: ``subfinder``/``crtsh``/
    ``resolve`` (ingest); ``probe``; ``gau``/``wayback``/``katana`` (crawl);
    ``scan``; ``fetch`` (secrets)."""
    scan_id = uuid.uuid4().hex
    audit = ScanRunRepo.from_mongo(mongo)

    common = dict(
        mongo=mongo,
        engine=engine,
        scope=scope,
        tenant=tenant,
        program_id=program_id,
        timeout=timeout,
    )
    ingest_kw = {k: injected[k] for k in ("subfinder", "crtsh", "resolve") if k in injected}
    crawl_kw = {k: injected[k] for k in ("gau", "wayback", "katana") if k in injected}
    # (name, coroutine factory) in execution order. secrets takes no timeout.
    stage_defs: list[tuple[str, Any]] = [
        ("ingest", lambda: run_ingest(**common, apex=apex, **ingest_kw)),
        (
            "probe",
            lambda: run_probe(
                **common, **({"probe": injected["probe"]} if "probe" in injected else {})
            ),
        ),
        ("crawl", lambda: run_crawl(**common, apex=apex, **crawl_kw)),
        (
            "scan",
            lambda: run_scan(
                **common, **({"scan": injected["scan"]} if "scan" in injected else {})
            ),
        ),
        (
            "secrets",
            lambda: run_secret_scan(
                mongo=mongo,
                engine=engine,
                scope=scope,
                tenant=tenant,
                program_id=program_id,
                **({"fetch": injected["fetch"]} if "fetch" in injected else {}),
            ),
        ),
    ]

    run = ScanRun(
        tenant_id=tenant.tenant_id,
        scan_id=scan_id,
        program_id=program_id,
        pipeline="full",
        status=ScanStatus.RUNNING,
        started_at=datetime.now(UTC),
        stages=[ScanStage(name=name) for name, _ in stage_defs],
    )
    await audit.save(run)

    results: dict[str, dict] = {}
    with bind_context(tenant.tenant_id, scan_id):
        for stage_obj, (name, factory) in zip(run.stages, stage_defs, strict=True):
            stage_obj.status = ScanStatus.RUNNING
            stage_obj.started_at = datetime.now(UTC)
            await audit.save(run)  # flip to running so the poller sees the stage start
            try:
                res = await factory()
            except Exception as exc:
                now = datetime.now(UTC)
                stage_obj.status = ScanStatus.FAILED
                stage_obj.finished_at = now
                run.status = ScanStatus.FAILED
                run.finished_at = now
                run.error = f"{name}: {type(exc).__name__}: {exc}"
                await audit.save(run)
                logger.error("pipeline failed for {} at stage {}: {}", program_id, name, exc)
                raise
            stage_obj.status = ScanStatus.SUCCESS
            stage_obj.finished_at = datetime.now(UTC)
            stage_obj.stats = {k: v for k, v in res.items() if isinstance(v, int)}
            results[name] = res
            await audit.save(run)  # flip to success (+ stats) after the stage completes

        run.status = ScanStatus.SUCCESS
        run.finished_at = datetime.now(UTC)
        run.stats = {
            "assets_new": results["ingest"]["new"],
            "endpoints_new": results["probe"]["new"] + results["crawl"]["new"],
            "findings_new": results["scan"]["new"],
            "secrets_new": results["secrets"]["new"],
        }
        await audit.save(run)
        return {"scan_id": scan_id, **results}


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
        mongo=mongo,
        engine=engine,
        scope=scope,
        tenant=tenant,
        program_id=program_id,
        apex=program["apex_domain"],
        timeout=timeout,
    )
