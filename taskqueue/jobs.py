"""Job definitions for the Redis-backed task queue (§4 taskqueue, ADR-0003).

A ``Job`` is the unit the scheduler enqueues and a worker pulls. It is intentionally
small and serialisable: identity of what to scan, which pipeline to run, and a
priority. The worker rebuilds the full ``RunContext`` (scope decision, limiter,
settings) at execution time so nothing stale is carried across the queue boundary.

Package named ``taskqueue`` (not ``queue``) to avoid shadowing the stdlib
``queue`` module — see ADR-0007.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class Priority(IntEnum):
    """Lower value = sooner. CVE/KEV-driven rescans jump the line."""

    KEV_PRIORITY = 0
    NEW_ASSET = 10
    NORMAL = 50
    BACKFILL = 90


@dataclass(frozen=True)
class Job:
    tenant_id: str
    program_id: str
    pipeline: str  # "ingest" | "probe" | "scan" | "crawl" | "port_scan" | ...
    target: str | None = None  # specific host/IP, or None for whole-program
    priority: int = Priority.NORMAL
    scan_id: str = ""
    reason: str = ""  # why this was enqueued (audit / debugging)
    payload: dict = field(default_factory=dict)

    def dedup_key(self) -> str:
        """Key used to collapse duplicate enqueues of the same work."""
        return f"{self.tenant_id}:{self.program_id}:{self.pipeline}:{self.target or '*'}"
