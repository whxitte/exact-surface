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
    logger.info("worker started (concurrency={})", settings.worker_concurrency)


async def shutdown(ctx: dict) -> None:  # arq lifecycle hook
    logger.info("worker shutting down")


class WorkerSettings:
    """arq WorkerSettings shape. Functions/redis wiring added in Phase B."""

    on_startup = startup
    on_shutdown = shutdown
    functions: list = []  # pipeline task callables registered in Phase B

    @property
    def max_jobs(self) -> int:
        return get_settings().worker_concurrency
