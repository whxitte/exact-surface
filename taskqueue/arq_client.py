"""arq/Redis queue client — the production enqueuer (ADR-0003).

Imported lazily so the codebase stays importable without arq/redis installed. The
scheduler is handed the enqueuer returned by :func:`make_enqueuer`; jobs are
deduplicated by ``Job.dedup_key`` via arq's ``_job_id`` so a still-queued job is
never enqueued twice.
"""

from __future__ import annotations

from typing import Any

from core.config import get_settings
from taskqueue.jobs import Job

PIPELINE_TASK = "run_pipeline_task"


async def create_pool() -> Any:  # pragma: no cover - needs a live redis
    from arq import create_pool
    from arq.connections import RedisSettings

    return await create_pool(RedisSettings.from_dsn(get_settings().redis_uri))


def make_enqueuer(pool: Any):
    """Return an async ``(Job) -> None`` enqueuer backed by an arq pool."""

    async def enqueue(job: Job) -> None:  # pragma: no cover - needs a live redis
        await pool.enqueue_job(
            PIPELINE_TASK,
            job.tenant_id,
            job.program_id,
            job.pipeline,
            _job_id=job.dedup_key(),
            _defer_by=0,
        )

    return enqueue
