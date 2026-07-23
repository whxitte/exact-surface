"""Worker entrypoint — pulls jobs, enforces scope + rate limits, runs pipelines.

The worker is the *only* place a job becomes real network activity, so it is where
the safety controls are assembled: it builds the fleet-shared politeness limiter
(§3.8b) and hands it to the pipelines, which enforce authorization and scope per
target and pace their in-process requests through it.

This docstring used to describe the worker handing modules a ``RunContext``
carrying the decision and limiter. It never did — nothing constructs a
``RunContext``, and until ADR-0012 nothing called the limiter at all. The real
paths are ``pipelines/dispatch.py`` and ``pipelines/orchestrate.py``.

arq is imported lazily so this module imports without the dependency present.
"""

from __future__ import annotations

from core.config import get_settings
from core.logging import logger
from core.ratelimit import build_limiter


async def startup(ctx: dict) -> None:  # arq lifecycle hook
    settings = get_settings()
    # The worker had NO logging config → default loguru format, no tenant/scan
    # context. Configure our format so worker logs are attributable and captured.
    from core.logging import configure_logging

    configure_logging(level=settings.log_level, json_logs=settings.is_prod)
    # The worker is where scanning actually happens, so it is where errors that
    # matter actually occur. Only the API used to initialise Sentry, which meant
    # every pipeline/tool failure on an unattended run was invisible.
    from core.observability import init_sentry

    init_sentry(settings)
    ctx["settings"] = settings
    # arq assigns ctx["redis"] before invoking on_startup. If that ever stops being
    # true, a silent fall back to the in-memory store would hand every replica its
    # own bucket and multiply the per-target rate by the replica count — the exact
    # bug ADR-0012 fixes. In prod, refuse to start instead: not scanning is
    # recoverable, an AUP breach that terminates the cloud account is not. This is
    # the same fail-closed stance as Settings.assert_prod_safe().
    redis = ctx.get("redis")
    if redis is None and settings.is_prod:
        raise RuntimeError(
            "no redis in worker ctx — refusing to start: the politeness ceiling "
            "would be per-process and every replica would multiply the target rate "
            "(§3.8b, ADR-0012)"
        )
    if redis is None:
        logger.warning("no shared rate-limit store — local ceiling only (dev/single-process)")
    ctx["limiter"] = build_limiter(settings, redis=redis)
    # The worker emits the metrics that actually describe scanning (stage
    # outcomes, run durations, politeness throttles) into a per-process registry.
    # arq gives it no HTTP server, so without this listener nothing can scrape it.
    if settings.metrics_enabled:
        from daemon.metrics_server import start_metrics_server

        ctx["metrics_server"] = start_metrics_server(settings.metrics_port)
    from db.mongo import get_mongo

    mongo = get_mongo()
    await mongo.connect()
    ctx["mongo"] = mongo
    # Build the scope engine from the shared Mongo feed (ADR-0014), falling back to
    # the bundled file. Held on ctx and passed to every task, so a scope-feed update
    # reaches this worker on its next restart — running the updater no longer no-ops.
    from db.scope_feed import build_scope_engine

    ctx["engine"] = await build_scope_engine(mongo, allow_private=settings.lab_allow_private)
    # Publish ScanRun updates + per-scan logs to the live bus so /activity reflects
    # scans advancing in real time. Best-effort — never block startup.
    try:
        from core.activity_bus import RedisActivityBus, install_scan_log_capture, set_bus

        set_bus(RedisActivityBus.connect(settings.redis_uri))
        install_scan_log_capture(min_level=settings.log_level)
    except Exception as exc:  # noqa: BLE001
        logger.warning("activity bus unavailable in worker: {}", exc)
    # License-gated update feed: pull the latest signed template/tool bundle on start
    # (a worker restarts often enough that this stays current). Best-effort; a lapsed
    # subscription is refused fresh detections by the feed.
    if settings.update_feed_url:
        try:
            from core.updates import check_for_updates

            result = await check_for_updates(mongo)
            if result.get("applied"):
                logger.info("update feed: now on bundle {}", result.get("version"))
        except Exception as exc:  # noqa: BLE001 - never block worker start on updates
            logger.warning("update check on startup skipped: {}", exc)
    logger.info("worker started (concurrency={})", settings.worker_concurrency)


async def shutdown(ctx: dict) -> None:  # arq lifecycle hook
    from daemon.metrics_server import stop_metrics_server

    stop_metrics_server(ctx.get("metrics_server"))
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
    from core.tenant import TenantContext
    from pipelines.orchestrate import run_program

    settings = ctx["settings"]
    return await run_program(
        mongo=ctx["mongo"],
        engine=ctx["engine"],  # built from the shared Mongo feed at startup (ADR-0014)
        tenant=TenantContext(tenant_id=tenant_id, actor_id=actor_id),
        program_id=program_id,
        timeout=settings.tool_default_timeout,
        scan_id=scan_id,
        force=force,
        limiter=ctx["limiter"],
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
    from core.tenant import TenantContext
    from pipelines.dispatch import run_pipeline

    settings = ctx["settings"]
    result = await run_pipeline(
        mongo=ctx["mongo"],
        engine=ctx["engine"],  # shared Mongo feed (ADR-0014)
        tenant=TenantContext(tenant_id=tenant_id),
        program_id=program_id,
        pipeline=pipeline,
        timeout=settings.tool_default_timeout,
        hmac_key=settings.secret_hash_key_bytes(),
        targets=tuple(targets or ()),
        limiter=ctx["limiter"],
    )
    await _emit_cascade(ctx, tenant_id, program_id, pipeline, result)
    return result


async def run_bypass_task(
    ctx: dict,
    tenant_id: str,
    program_id: str,
    scan_id: str | None = None,
    targets: list[str] | None = None,
) -> dict:
    """arq task: run the on-demand 403-bypass for a program (user-triggered only).

    Not a pipeline phase and never enqueued by the scheduler — the API enqueues it when
    a user clicks "Try 403 bypass". Reuses the shared engine + politeness limiter so it
    stays scope- and rate-safe, and reuses ``scan_id`` so the queued Activity row is the
    one that goes RUNNING."""
    from core.tenant import TenantContext
    from pipelines.bypass_403 import run_bypass_scan

    settings = ctx["settings"]
    return await run_bypass_scan(
        mongo=ctx["mongo"],
        engine=ctx["engine"],
        tenant=TenantContext(tenant_id=tenant_id),
        program_id=program_id,
        scan_id=scan_id,
        targets=tuple(targets or ()),
        limiter=ctx["limiter"],
        timeout=settings.tool_default_timeout,
    )


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

    functions = [run_program_task, run_pipeline_task, run_bypass_task]
    on_startup = startup
    on_shutdown = shutdown
    max_jobs = get_settings().worker_concurrency
    # A full pipeline runs 5 stages sequentially; the default 300s would cancel it
    # mid-crawl (→ CancelledError → stuck RUNNING). Give it room; stages self-bound.
    job_timeout = get_settings().worker_job_timeout
    redis_settings = _redis_settings()
