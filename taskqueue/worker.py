"""Worker entrypoint — pulls jobs, enforces scope + rate limits, runs pipelines.

The worker is the *only* place a job becomes real network activity, and it is the
choke point where safety is enforced: before running any pipeline it (1) confirms a
current authorization record exists for the program, (2) resolves the target and
obtains a :class:`~core.scope.ScopeDecision`, and (3) hands the module a
``RunContext`` carrying that decision + the shared politeness limiter. A module can
only act within the permitted action set.

arq is imported lazily so this module imports without the dependency present.
Phase A ships the context-assembly contract; the arq wiring lands in Phase B.
"""

from __future__ import annotations

from core.config import Settings, get_settings
from core.logging import logger
from core.ratelimit import InMemoryBucketStore, PolitenessLimiter, RateLimit


def build_limiter(settings: Settings, store=None) -> PolitenessLimiter:
    """Construct the process's politeness limiter from settings.

    Uses an in-memory store by default; the worker fleet passes a
    :class:`~core.ratelimit.RedisBucketStore` so the ceiling is shared across
    workers (§3.8b).
    """
    limit = RateLimit.per_second(settings.global_rate_per_target)
    return PolitenessLimiter(store or InMemoryBucketStore(), default_limit=limit)


async def startup(ctx: dict) -> None:  # arq lifecycle hook
    settings = get_settings()
    # The worker had NO logging config → default loguru format, no tenant/scan
    # context. Configure our format so worker logs are attributable and captured.
    from core.logging import configure_logging

    configure_logging(level=settings.log_level, json_logs=settings.is_prod)
    ctx["settings"] = settings
    ctx["limiter"] = build_limiter(settings)
    from db.mongo import get_mongo

    mongo = get_mongo()
    await mongo.connect()
    ctx["mongo"] = mongo
    # Publish ScanRun updates + per-scan logs to the live bus so /activity reflects
    # scans advancing in real time. Best-effort — never block startup.
    try:
        from core.activity_bus import RedisActivityBus, install_scan_log_capture, set_bus

        set_bus(RedisActivityBus.connect(settings.redis_uri))
        install_scan_log_capture(min_level=settings.log_level)
    except Exception as exc:  # noqa: BLE001
        logger.warning("activity bus unavailable in worker: {}", exc)
    logger.info("worker started (concurrency={})", settings.worker_concurrency)


async def shutdown(ctx: dict) -> None:  # arq lifecycle hook
    mongo = ctx.get("mongo")
    if mongo is not None:
        await mongo.close()
    logger.info("worker shutting down")


async def run_program_task(
    ctx: dict,
    tenant_id: str,
    program_id: str,
    actor_id: str | None = None,
    scan_id: str | None = None,
    force: bool = False,
) -> dict:
    """arq task: run the FULL pipeline for a program (used by the API scan trigger).

    ``scan_id`` (passed by the API) reuses the QUEUED ScanRun created at enqueue so
    the button click shows immediately and no duplicate row is created. ``force`` is
    set for an explicit user scan so it runs even if monitoring is paused; the
    scheduler's bootstrap leaves it False so a paused program is skipped.
    """
    from core.scope import default_engine
    from core.tenant import TenantContext
    from pipelines.orchestrate import run_program

    settings = ctx["settings"]
    return await run_program(
        mongo=ctx["mongo"],
        engine=default_engine(),
        tenant=TenantContext(tenant_id=tenant_id, actor_id=actor_id),
        program_id=program_id,
        timeout=settings.tool_default_timeout,
        scan_id=scan_id,
        force=force,
    )


async def run_pipeline_task(
    ctx: dict,
    tenant_id: str,
    program_id: str,
    pipeline: str,
    targets: list[str] | None = None,
) -> dict:
    """arq task: run ONE named pipeline for a program (enqueued by the scheduler).

    ``targets`` (optional hostnames) scopes the run to specific assets — set by the
    event-driven cascade so a newly discovered host flows straight through the
    downstream phases. After the run, new discoveries fan out to the next phases.
    """
    from core.scope import default_engine
    from core.tenant import TenantContext
    from pipelines.dispatch import run_pipeline

    settings = ctx["settings"]
    result = await run_pipeline(
        mongo=ctx["mongo"],
        engine=default_engine(),
        tenant=TenantContext(tenant_id=tenant_id),
        program_id=program_id,
        pipeline=pipeline,
        timeout=settings.tool_default_timeout,
        hmac_key=settings.secret_hash_key_bytes(),
        targets=tuple(targets or ()),
    )
    await _emit_cascade(ctx, tenant_id, program_id, pipeline, result)
    return result


async def _emit_cascade(
    ctx: dict, tenant_id: str, program_id: str, pipeline: str, result: dict
) -> None:
    """Enqueue the downstream phases for whatever this phase newly discovered.

    Best-effort: a cascade failure must never fail a phase that already succeeded —
    the periodic cadence still picks the work up."""
    try:
        from taskqueue.arq_client import make_enqueuer
        from taskqueue.cascade import cascade_jobs

        jobs = cascade_jobs(
            pipeline=pipeline, result=result, tenant_id=tenant_id, program_id=program_id
        )
        pool = ctx.get("redis")
        if not jobs or pool is None:
            return
        enqueue = make_enqueuer(pool)
        for job in jobs:
            await enqueue(job)
        logger.info(
            "cascade: {} → {} follow-on job(s) [{}]",
            pipeline,
            len(jobs),
            ", ".join(sorted({j.pipeline for j in jobs})),
        )
    except Exception as exc:  # noqa: BLE001 - cascade is best-effort
        logger.warning("cascade after {} failed: {}", pipeline, exc)


def _redis_settings():
    """arq RedisSettings from the configured redis_uri (evaluated at worker start)."""
    from arq.connections import RedisSettings

    return RedisSettings.from_dsn(get_settings().redis_uri)


class WorkerSettings:
    """arq reads these as CLASS attributes — they must be plain values, not properties."""

    functions = [run_program_task, run_pipeline_task]
    on_startup = startup
    on_shutdown = shutdown
    max_jobs = get_settings().worker_concurrency
    # A full pipeline runs 5 stages sequentially; the default 300s would cancel it
    # mid-crawl (→ CancelledError → stuck RUNNING). Give it room; stages self-bound.
    job_timeout = get_settings().worker_job_timeout
    redis_settings = _redis_settings()
