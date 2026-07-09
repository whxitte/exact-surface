"""Event-driven cascade (§continuous engine).

When a *scheduled* phase discovers something new, the downstream phases should run
for JUST those new assets immediately — not wait for their own cadence tick. That
is the fast attack-surface-discovery path the product promises: a customer adds a
domain and every follow-on phase chases each discovery through the attacker chain.

The scheduler still drives periodic whole-program re-scans (cadence); this is the
*reactive* layer on top. A worker calls :func:`cascade_jobs` after running a phase
and enqueues whatever it returns (targeted at the new hostnames, high priority).
"""

from __future__ import annotations

from typing import Any

from taskqueue.jobs import Job, Priority

#: phase -> downstream phases to trigger on new discoveries. Targets are hostnames.
#: notify is program-wide (delivers new findings to channels), so it is triggered by
#: a "new items" count rather than by a target set.
CASCADE: dict[str, tuple[str, ...]] = {
    "ingest": ("probe",),
    "probe": ("crawl", "port_scan"),
    "crawl": ("scan", "secrets"),
    "scan": ("notify",),
    "secrets": ("notify",),
}

_PROGRAM_WIDE = {"notify"}


def cascade_jobs(*, pipeline: str, result: Any, tenant_id: str, program_id: str) -> list[Job]:
    """Jobs to enqueue after *pipeline* finished with *result*.

    A phase reports the hostnames it newly discovered in ``result["cascade_targets"]``
    (probe/crawl/ingest) and/or a ``result["new"]`` count (scan/secrets → notify).
    Skipped phases and phases with nothing new produce no cascade.
    """
    if not isinstance(result, dict) or result.get("skipped"):
        return []
    downstream = CASCADE.get(pipeline, ())
    if not downstream:
        return []

    targets = tuple(dict.fromkeys(result.get("cascade_targets") or []))  # dedup, keep order
    has_new = int(result.get("new", 0) or 0) > 0
    jobs: list[Job] = []
    for nxt in downstream:
        if nxt in _PROGRAM_WIDE:
            if has_new:
                jobs.append(
                    Job(
                        tenant_id=tenant_id,
                        program_id=program_id,
                        pipeline=nxt,
                        priority=Priority.NEW_ASSET,
                        reason=f"cascade:{pipeline}",
                    )
                )
        elif targets:
            jobs.append(
                Job(
                    tenant_id=tenant_id,
                    program_id=program_id,
                    pipeline=nxt,
                    targets=targets,
                    priority=Priority.NEW_ASSET,
                    reason=f"cascade:{pipeline}",
                )
            )
    return jobs
