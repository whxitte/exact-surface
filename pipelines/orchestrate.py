"""Full-pipeline orchestration: ingest → probe → scan for one program.

This is what a worker runs for a program. It (1) refuses to proceed without a
current authorization record (§9b/§9e), (2) builds the ``ProgramScope`` from the
program + authorization, (3) runs the three pipelines in order, and (4) records a
``ScanRun`` audit row with per-stage stats.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime
from typing import Any

from core.config import get_settings
from core.errors import AuthorizationRequired
from core.logging import bind_context, logger
from core.models import ScanRun, ScanStage, ScanStatus
from core.scope import ProgramScope, ScopeEngine
from core.tenant import TenantContext
from db.audit import ScanRunRepo
from db.authorizations import AuthorizationRepo
from db.programs import ProgramRepo
from pipelines.content_discovery import run_content_discovery
from pipelines.correlate import run_correlate
from pipelines.crawl import run_crawl
from pipelines.cve_watch import run_cve_watch
from pipelines.dork import run_dork
from pipelines.github_osint import run_github_leak_scan
from pipelines.ingest import run_ingest
from pipelines.notify import run_notify
from pipelines.port_scan import run_port_scan
from pipelines.probe import run_probe
from pipelines.scan import run_scan
from pipelines.secrets import run_secret_scan
from pipelines.service_scan import run_service_scan
from pipelines.tls import run_tls_scan


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
        scan_shared_infra=bool(program.get("scan_shared_infra", False)),
    )


def _auth_is_current(auth: dict | None) -> bool:
    return bool(auth and auth.get("apex_verified") and not auth.get("revoked"))


#: optional modules — off by default, toggled per program via ``enabled_modules``.
#: Each has a stage in the pipeline that renders as a (gray) SKIPPED node when the
#: module is disabled, and runs its tool when enabled.
OPTIONAL_MODULES: tuple[str, ...] = ("tls", "service_scan", "dork")

#: canonical full-pipeline stage order — the complete outside-in attacker chain,
#: shared with the API so an enqueue-time QUEUED ScanRun pre-renders the same
#: stepper. Core stages self-skip when they have nothing to do; the OPTIONAL_MODULES
#: stages self-skip as "disabled" unless enabled for the program.
FULL_STAGE_NAMES: tuple[str, ...] = (
    "ingest",
    "probe",
    "tls",  # optional
    "crawl",
    "content_discovery",
    "port_scan",
    "service_scan",  # optional
    "scan",
    "secrets",
    "cve_watch",
    "github_osint",
    "dork",  # optional
    "correlate",
    "notify",
)


async def run_full_pipeline(
    *,
    mongo: Any,
    engine: ScopeEngine,
    scope: ProgramScope,
    tenant: TenantContext,
    program_id: str,
    apex: str,
    timeout: float,
    scan_id: str | None = None,
    enabled_modules: tuple[str, ...] = (),
    **injected: Any,
) -> dict:
    """Run the full outside-in pipeline: discover → probe → (tls) → crawl → content
    → ports → (services) → scan → secrets → CVE → GitHub OSINT → (dork) → correlate
    → notify.

    ``scan_id`` reuses a pre-created (QUEUED) ScanRun so the API's enqueue-time row
    becomes this run rather than a second row; omitted, a fresh id is generated.
    ``enabled_modules`` turns on the OPTIONAL_MODULES stages (else they render as a
    disabled/gray node). ``injected`` forwards test doubles per stage."""
    scan_id = scan_id or uuid.uuid4().hex
    audit = ScanRunRepo.from_mongo(mongo)

    common = dict(
        mongo=mongo,
        engine=engine,
        scope=scope,
        tenant=tenant,
        program_id=program_id,
        timeout=timeout,
    )
    core = dict(mongo=mongo, tenant=tenant, program_id=program_id)  # DB-only stages

    def inj(*keys: str) -> dict:
        return {k: injected[k] for k in keys if k in injected}

    enabled = set(enabled_modules)

    async def _disabled() -> dict:
        return {"skipped": True, "disabled": True, "note": "not enabled — turn on in settings"}

    def optional(module: str, real):
        """Run *real* (a zero-arg factory) only if the module is enabled; else the
        stage renders as a disabled node."""
        return real if module in enabled else _disabled

    # (name, coroutine factory) in execution order — the complete attacker chain.
    # OPTIONAL_MODULES stages (tls/service_scan/dork) self-skip when not enabled.
    stage_defs: list[tuple[str, Any]] = [
        ("ingest", lambda: run_ingest(**common, apex=apex, **inj("subfinder", "crtsh", "resolve"))),
        ("probe", lambda: run_probe(**common, **inj("probe"))),
        ("tls", optional("tls", lambda: run_tls_scan(**common, **inj("tlsinspect")))),
        ("crawl", lambda: run_crawl(**common, apex=apex, **inj("gau", "wayback", "katana"))),
        ("content_discovery", lambda: run_content_discovery(**common, **inj("discover"))),
        ("port_scan", lambda: run_port_scan(**common, **inj("naabu"))),
        (
            "service_scan",
            optional("service_scan", lambda: run_service_scan(**common, **inj("nmap"))),
        ),
        ("scan", lambda: run_scan(**common, **inj("scan"))),
        (
            "secrets",
            lambda: run_secret_scan(
                mongo=mongo,
                engine=engine,
                scope=scope,
                tenant=tenant,
                program_id=program_id,
                **inj("fetch"),
            ),
        ),
        ("cve_watch", lambda: run_cve_watch(**core, **inj("recent", "kev"))),
        ("github_osint", lambda: run_github_leak_scan(**core, domain=apex, **inj("search"))),
        (
            "dork",
            optional(
                "dork",
                lambda: run_dork(
                    **core,
                    domain=apex,
                    **({"search": injected["dork_search"]} if "dork_search" in injected else {}),
                ),
            ),
        ),
        ("correlate", lambda: run_correlate(**core)),
        ("notify", lambda: run_notify(**core, **inj("senders"))),
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

    stage_budget = get_settings().stage_timeout
    results: dict[str, dict] = {}
    with bind_context(tenant_id=tenant.tenant_id, scan_id=scan_id, program_id=program_id):
        logger.info("full scan started: {} ({} stages)", apex, len(stage_defs))
        for stage_obj, (name, factory) in zip(run.stages, stage_defs, strict=True):
            with bind_context(pipeline=name):
                stage_obj.status = ScanStatus.RUNNING
                stage_obj.started_at = datetime.now(UTC)
                await audit.save(run)  # flip to running so the poller sees the stage start
                logger.info("stage {} started", name)
                try:
                    # Hard per-stage ceiling: a stuck stage raises TimeoutError (caught
                    # below → clean FAILED) rather than hanging until arq hard-cancels.
                    res = await asyncio.wait_for(factory(), stage_budget)
                except (Exception, asyncio.CancelledError) as exc:
                    now = datetime.now(UTC)
                    timed_out = isinstance(exc, (asyncio.TimeoutError, asyncio.CancelledError))
                    stage_obj.status = ScanStatus.FAILED
                    stage_obj.finished_at = now
                    run.status = ScanStatus.FAILED
                    run.finished_at = now
                    run.error = (
                        f"{name}: timed out"
                        if timed_out
                        else f"{name}: {type(exc).__name__}: {exc}"
                    )
                    # shield: if this is an outer cancellation, still persist FAILED
                    # rather than leaving the run stuck RUNNING.
                    await asyncio.shield(audit.save(run))
                    logger.error("pipeline failed for {} at stage {}: {}", program_id, name, exc)
                    raise
                stage_obj.finished_at = datetime.now(UTC)
                if res.get("skipped"):
                    stage_obj.status = ScanStatus.SKIPPED
                    stage_obj.note = res.get("note")
                else:
                    stage_obj.status = ScanStatus.SUCCESS
                    stage_obj.stats = {k: v for k, v in res.items() if isinstance(v, int)}
                results[name] = res
                await audit.save(run)  # flip to done (+ stats/note) after the stage completes

        run.status = ScanStatus.SUCCESS
        run.finished_at = datetime.now(UTC)
        run.stats = {
            "assets_new": results["ingest"]["new"],
            "endpoints_new": (
                results["probe"]["new"]
                + results["crawl"]["new"]
                + results["content_discovery"]["new"]
            ),
            "ports_new": results["port_scan"]["new"],
            "findings_new": results["scan"]["new"],
            "secrets_new": results["secrets"]["new"],
            "cve_matches": results["cve_watch"]["new_alertable"],
            "issues": results["correlate"]["count"],
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
    scan_id: str | None = None,
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
    result = await run_full_pipeline(
        mongo=mongo,
        engine=engine,
        scope=scope,
        tenant=tenant,
        program_id=program_id,
        apex=program["apex_domain"],
        timeout=timeout,
        scan_id=scan_id,
        enabled_modules=tuple(program.get("enabled_modules", [])),
    )
    # Once the first full run finishes, the scheduler switches this program from
    # bootstrap to per-phase cadence. Set only on the first completion.
    if program.get("initial_scan_completed_at") is None:
        await ProgramRepo.from_mongo(mongo).mark_initial_scan_completed(
            tenant.tenant_id, program_id, datetime.now(UTC)
        )
    return result
