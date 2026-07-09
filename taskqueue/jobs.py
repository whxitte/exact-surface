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
    targets: tuple[str, ...] = ()  # cascade: scope this run to these hostnames
    priority: int = Priority.NORMAL
    scan_id: str = ""
    reason: str = ""  # why this was enqueued (audit / debugging)
    payload: dict = field(default_factory=dict)

    def dedup_key(self) -> str:
        """Key used to collapse duplicate enqueues of the same work. A targeted
        (cascade) job dedups on a hash of its target set, so it never collides with
        the whole-program cadence job for the same pipeline."""
        if self.targets:
            import hashlib

            # dedup key only — not security-sensitive, so sha1 (fast) is fine
            joined = ",".join(sorted(self.targets)).encode()
            digest = hashlib.sha1(joined, usedforsecurity=False).hexdigest()[:12]
            scope = f"t:{digest}"
        else:
            scope = self.target or "*"
        return f"{self.tenant_id}:{self.program_id}:{self.pipeline}:{scope}"
