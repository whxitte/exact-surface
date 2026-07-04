"""Pipeline cadence policy (§7 Phase D / continuous engine).

Each pipeline runs on its own interval — the CVE watch is fast (new KEV entries
matter in minutes), full re-enumeration is slow. The scheduler consults these
intervals plus per-(program,pipeline) last-run state to decide what is *due*, so
unchanged assets are not needlessly re-scanned (§3.1 state-awareness).
"""

from __future__ import annotations

from datetime import datetime

MINUTE = 60
HOUR = 60 * MINUTE

#: pipeline -> interval seconds. Fast signals first.
DEFAULT_CADENCE_SECONDS: dict[str, int] = {
    "notify": 1 * MINUTE,  # deliver new findings to channels within a tick
    "cve_watch": 15 * MINUTE,  # new CVE/KEV → matched-asset alert fast
    "probe": 2 * HOUR,  # re-probe alive endpoints (also emits deltas)
    "ingest": 6 * HOUR,  # re-enumerate subdomains
    "scan": 12 * HOUR,  # full nuclei re-scan
    "crawl": 24 * HOUR,
    "port_scan": 24 * HOUR,
    "content_discovery": 24 * HOUR,
    "secrets": 24 * HOUR,
    "github_osint": 24 * HOUR,
}


def is_due(last_run: datetime | None, now: datetime, interval_seconds: int) -> bool:
    """True if a pipeline that last ran at *last_run* is due again at *now*.

    Never-run (``last_run is None``) is always due — a brand-new program gets
    scanned immediately.
    """
    if last_run is None:
        return True
    return (now - last_run).total_seconds() >= interval_seconds
