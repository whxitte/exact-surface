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
    ctx["settings"] = settings
    ctx["limiter"] = build_limiter(settings)
    from db.mongo import get_mongo

    mongo = get_mongo()
    await mongo.connect()
    ctx["mongo"] = mongo
    logger.info("worker started (concurrency={})", settings.worker_concurrency)


async def shutdown(ctx: dict) -> None:  # arq lifecycle hook
    mongo = ctx.get("mongo")
    if mongo is not None:
        await mongo.close()
    logger.info("worker shutting down")


async def run_program_task(
    ctx: dict, tenant_id: str, program_id: str, actor_id: str | None = None
) -> dict:
    """arq task: run the FULL pipeline for a program (used by the API scan trigger)."""
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
    )


async def run_pipeline_task(ctx: dict, tenant_id: str, program_id: str, pipeline: str) -> dict:
    """arq task: run ONE named pipeline for a program (enqueued by the scheduler)."""
    from core.scope import default_engine
    from core.tenant import TenantContext
    from pipelines.dispatch import run_pipeline

    settings = ctx["settings"]
    return await run_pipeline(
        mongo=ctx["mongo"],
        engine=default_engine(),
        tenant=TenantContext(tenant_id=tenant_id),
        program_id=program_id,
        pipeline=pipeline,
        timeout=settings.tool_default_timeout,
        hmac_key=settings.secret_hash_key_bytes(),
    )


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
    redis_settings = _redis_settings()
