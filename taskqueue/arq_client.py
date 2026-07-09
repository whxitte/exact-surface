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
PROGRAM_TASK = "run_program_task"
#: pseudo-pipeline name the scheduler uses for the ordered full run.
FULL_PIPELINE = "full"


async def create_pool() -> Any:  # pragma: no cover - needs a live redis
    from arq import create_pool
    from arq.connections import RedisSettings

    return await create_pool(RedisSettings.from_dsn(get_settings().redis_uri))


def make_enqueuer(pool: Any):
    """Return an async ``(Job) -> None`` enqueuer backed by an arq pool."""

    async def enqueue(job: Job) -> None:  # pragma: no cover - needs a live redis
        if job.pipeline == FULL_PIPELINE:
            # bootstrap: run the ordered full pipeline via run_program_task
            await pool.enqueue_job(
                PROGRAM_TASK,
                job.tenant_id,
                job.program_id,
                None,  # actor_id
                job.scan_id or None,
                _job_id=job.dedup_key(),
                _defer_by=0,
            )
            return
        await pool.enqueue_job(
            PIPELINE_TASK,
            job.tenant_id,
            job.program_id,
            job.pipeline,
            list(job.targets),  # cascade: hostnames to scope this run to ([] = whole program)
            _job_id=job.dedup_key(),
            _defer_by=0,
        )

    return enqueue
