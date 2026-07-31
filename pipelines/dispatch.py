"""Pipeline dispatch — run one named pipeline for a program (auth-gated).

The worker calls this for each scheduled job. It loads the program + authorization,
refuses without a current authorization (§9b/§9e), builds the ``ProgramScope``, and
routes to the right pipeline. Centralising the routing keeps the worker thin and
the scope/auth enforcement in one place.

Routing lives in :data:`ROUTES`, a table keyed by module name, rather than an
if-chain. That is deliberate: every module in :mod:`core.modules` must have an entry,
and ``tests/unit/test_dispatch.py`` asserts exactly that. When the table was a chain
of ``if`` statements, adding a module to the registry and its cadence without adding
it here was silent — the scheduler happily enqueued ``js_mine`` every night and every
run died with "unknown pipeline". The table makes that a failing test instead.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from core import modules as module_registry
from core.errors import AuthorizationRequired
from core.ratelimit import PolitenessLimiter
from core.scope import ProgramScope, ScopeEngine
from core.tenant import TenantContext
from db.authorizations import AuthorizationRepo
from db.programs import ProgramRepo
from pipelines.api_surface import run_api_surface
from pipelines.broken_links import run_broken_links
from pipelines.cloud_buckets import run_cloud_buckets
from pipelines.content_discovery import run_content_discovery
from pipelines.correlate import run_correlate
from pipelines.crawl import run_crawl
from pipelines.cve_watch import run_cve_watch
from pipelines.domain_intel import run_domain_intel
from pipelines.dork import run_dork
from pipelines.github_osint import run_github_leak_scan
from pipelines.http_misconfig import run_http_misconfig
from pipelines.ingest import run_ingest
from pipelines.js_mine import run_js_mine
from pipelines.notify import run_notify
from pipelines.nuclei_watch import run_nuclei_watch
from pipelines.orchestrate import build_program_scope
from pipelines.param_discovery import run_param_discovery
from pipelines.port_scan import run_port_scan
from pipelines.probe import run_probe
from pipelines.reverse_dns import run_reverse_dns
from pipelines.scan import run_scan
from pipelines.secrets import run_secret_scan
from pipelines.service_scan import run_service_scan
from pipelines.supply_chain import run_supply_chain
from pipelines.takeover import run_takeover
from pipelines.tls import run_tls_scan
from pipelines.typosquat import run_typosquat
from pipelines.uncover import run_uncover


@dataclass(frozen=True)
class Ctx:
    """Everything a single-phase run needs. Built once, handed to the route."""

    mongo: Any
    engine: ScopeEngine
    scope: ProgramScope
    tenant: TenantContext
    program_id: str
    apex: str
    timeout: float
    hmac_key: bytes | None = None
    limiter: PolitenessLimiter | None = None
    #: hostnames a cascade run is narrowed to; None = the whole program
    targets: set[str] | None = None

    @property
    def scanning(self) -> dict:
        """Args for stages that reach out to hosts: scope, engine and a tool budget."""
        return {
            "mongo": self.mongo,
            "engine": self.engine,
            "scope": self.scope,
            "tenant": self.tenant,
            "program_id": self.program_id,
            "timeout": self.timeout,
        }

    @property
    def core(self) -> dict:
        """Args for stages that only read and write the database."""
        return {"mongo": self.mongo, "tenant": self.tenant, "program_id": self.program_id}


#: module name -> how to run it. Keys must cover ``core.modules.MODULE_NAMES``.
ROUTES: dict[str, Callable[[Ctx], Awaitable[dict]]] = {
    "domain_intel": lambda c: run_domain_intel(**c.core, apex=c.apex),
    "ingest": lambda c: run_ingest(**c.scanning, apex=c.apex),
    "uncover": lambda c: run_uncover(**c.scanning, apex=c.apex),
    "reverse_dns": lambda c: run_reverse_dns(
        mongo=c.mongo,
        scope=c.scope,
        tenant=c.tenant,
        program_id=c.program_id,
        timeout=c.timeout,
    ),
    "probe": lambda c: run_probe(**c.scanning, targets=c.targets),
    "tls": lambda c: run_tls_scan(**c.scanning),
    "takeover": lambda c: run_takeover(**c.scanning, limiter=c.limiter),
    "crawl": lambda c: run_crawl(**c.scanning, apex=c.apex, targets=c.targets),
    "content_discovery": lambda c: run_content_discovery(**c.scanning),
    "js_mine": lambda c: run_js_mine(**c.scanning, limiter=c.limiter),
    "api_surface": lambda c: run_api_surface(**c.scanning, limiter=c.limiter),
    "http_misconfig": lambda c: run_http_misconfig(**c.scanning, limiter=c.limiter),
    "param_discovery": lambda c: run_param_discovery(**c.scanning, limiter=c.limiter),
    "supply_chain": lambda c: run_supply_chain(**c.core, timeout=c.timeout),
    "typosquat": lambda c: run_typosquat(**c.core, apex=c.apex, timeout=c.timeout),
    "broken_links": lambda c: run_broken_links(
        mongo=c.mongo,
        scope=c.scope,
        tenant=c.tenant,
        program_id=c.program_id,
        timeout=c.timeout,
        limiter=c.limiter,
    ),
    "port_scan": lambda c: run_port_scan(**c.scanning, targets=c.targets),
    "service_scan": lambda c: run_service_scan(**c.scanning),
    "scan": lambda c: run_scan(**c.scanning, targets=c.targets),
    "secrets": lambda c: run_secret_scan(
        mongo=c.mongo,
        engine=c.engine,
        scope=c.scope,
        tenant=c.tenant,
        program_id=c.program_id,
        hmac_key=c.hmac_key,
        targets=c.targets,
        limiter=c.limiter,
    ),
    "cve_watch": lambda c: run_cve_watch(**c.core),
    "github_osint": lambda c: run_github_leak_scan(
        **c.core, domain=c.apex, hmac_key=c.hmac_key
    ),
    "cloud_buckets": lambda c: run_cloud_buckets(**c.core, apex=c.apex),
    "nuclei_watch": lambda c: run_nuclei_watch(**c.core),
    "dork": lambda c: run_dork(**c.core, domain=c.apex),
    "correlate": lambda c: run_correlate(**c.core),
    "notify": lambda c: run_notify(**c.core),
}


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
    targets: tuple[str, ...] = (),
    limiter: PolitenessLimiter | None = None,
) -> dict:
    # Subscription gate (self-hosted licensing): a read-only instance (expired past
    # grace / missing / tampered) does no scanning — the authoritative stop for
    # scheduled work, mirroring the API's per-request guard. No-op when unenforced.
    from core.entitlements import ensure_fresh

    if (await ensure_fresh(mongo)).read_only:
        from core.logging import logger

        logger.info("license read-only — skipping {} for {}", pipeline, program_id)
        return {"skipped": True, "note": "subscription read-only"}

    program = await ProgramRepo.from_mongo(mongo).get(tenant.tenant_id, program_id)
    if not program:
        raise AuthorizationRequired(f"no program {program_id} for tenant {tenant.tenant_id}")
    # Respect the pause at EXECUTION time, not just at scheduling: a job may have
    # been enqueued (and persisted in Redis) before the program was paused, or
    # before a restart. All jobs reaching dispatch are automated (scheduler /
    # cascade), so a paused program simply no-ops.
    if not program.get("enabled", True):
        from core.logging import logger

        logger.info("{} is paused (monitoring off) — skipping {}", program_id, pipeline)
        return {"skipped": True, "note": "monitoring paused"}
    auth = await AuthorizationRepo.from_mongo(mongo).get(tenant.tenant_id, program_id)
    if not _auth_current(auth):
        raise AuthorizationRequired(f"no current authorization for program {program_id}")

    # A module the user switched off (or whose dependency is off) must not run, whatever
    # enqueued it. The scheduler already filters its own fan-out, but the cascade does
    # not — a new host found by crawl would otherwise trigger a `scan` the settings
    # screen says is disabled. Dispatch is where every automated path converges, so the
    # gate belongs here.
    module_state = module_registry.resolve(
        enabled_modules=program.get("enabled_modules"),
        disabled_modules=program.get("disabled_modules"),
    )
    if pipeline in module_registry.BY_NAME and not module_state.is_enabled(pipeline):
        from core.logging import logger

        reason = module_state.reason(pipeline) or "not enabled"
        logger.info("{} is disabled for {} ({}) — skipping", pipeline, program_id, reason)
        return {"skipped": True, "note": reason}

    scope = build_program_scope(program, auth)
    apex = program["apex_domain"]
    # cascade: when a job carries specific hostnames, phases scope their work to them
    tset: set[str] | None = set(targets) or None
    # per-phase timeout (built-ins ← tenant ← program) so a single-phase cadence /
    # cascade run of e.g. `scan` gets the same configurable nuclei budget as a full run.
    from db.tenants import TenantRepo
    from taskqueue.timeouts import effective_timeouts

    tenant_doc = await TenantRepo.from_mongo(mongo).get(tenant.tenant_id)
    timeouts = effective_timeouts(
        program.get("timeout_overrides"), (tenant_doc or {}).get("timeout_overrides")
    )
    phase_timeout = timeouts.get(pipeline, timeout)
    ctx = Ctx(
        mongo=mongo,
        engine=engine,
        scope=scope,
        tenant=tenant,
        program_id=program_id,
        apex=apex,
        timeout=phase_timeout,
        hmac_key=hmac_key,
        limiter=limiter,
        targets=tset,
    )

    route = ROUTES.get(pipeline)
    if route is None:
        raise ValueError(f"unknown pipeline: {pipeline}")

    async def _execute() -> dict:
        return await route(ctx)

    # Record a ScanRun so every pipeline execution is visible in the activity feed.
    import asyncio
    import uuid
    from datetime import UTC, datetime

    from core.logging import bind_context, logger
    from core.models import ScanRun, ScanStatus
    from db.audit import ScanRunRepo

    audit = ScanRunRepo.from_mongo(mongo)
    heartbeat = 45  # re-save updated_at this often so a slow phase reads as alive

    # One whole-program run of a phase at a time: if a genuinely-alive one is already in
    # flight (e.g. a slow nuclei scan), skip this duplicate instead of piling on. Cascade
    # (target-scoped) runs are exempt — they cover a specific new host and are small.
    if not tset and await audit.active_phase_run(
        tenant.tenant_id, program_id, pipeline, fresh_seconds=3 * heartbeat
    ):
        logger.info("{} already running for {} — skipping duplicate", pipeline, program_id)
        return {"skipped": True, "note": f"{pipeline} already running"}

    run = ScanRun(
        tenant_id=tenant.tenant_id,
        scan_id=uuid.uuid4().hex,
        program_id=program_id,
        pipeline=pipeline,
        status=ScanStatus.RUNNING,
        started_at=datetime.now(UTC),
        # cascade runs carry targets → not full coverage; the gone-detector ignores them.
        targets=list(targets),
    )
    # Attribute every log line from this cadence run (tenant/program/scan/pipeline)
    # — the scheduler path previously logged with no context (t=- s=-).
    with bind_context(
        tenant_id=tenant.tenant_id,
        scan_id=run.scan_id,
        program_id=program_id,
        pipeline=pipeline,
    ):
        await audit.save(run)
        logger.info("{} started", pipeline)
        # Heartbeat updated_at while the phase runs, so a long stage (nuclei can run for
        # ~an hour) reads as RUNNING in the feed instead of being mislabelled "stalled",
        # and the duplicate-guard above can tell an alive run from a dead one.
        task = asyncio.ensure_future(_execute())
        try:
            while True:
                done, _ = await asyncio.wait({task}, timeout=heartbeat)
                if task in done:
                    break
                run.updated_at = datetime.now(UTC)
                await audit.save(run)
            result = task.result()
        except Exception as exc:
            task.cancel()
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
