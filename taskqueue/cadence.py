"""Pipeline cadence policy (§7 Phase D / continuous engine).

Each pipeline runs on its own interval — the CVE watch is fast (new KEV entries
matter in minutes), full re-enumeration is slow. The scheduler consults these
intervals plus per-(program,pipeline) last-run state to decide what is *due*, so
unchanged assets are not needlessly re-scanned (§3.1 state-awareness).
"""

from __future__ import annotations

from datetime import datetime, timedelta

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
    "takeover": 24 * HOUR,  # re-check dangling CNAMEs daily
    "port_scan": 24 * HOUR,
    "content_discovery": 24 * HOUR,
    "secrets": 24 * HOUR,
    "github_osint": 24 * HOUR,
    # Newer stages. domain_intel is passive and cheap, so it can run often; js_mine and
    # broken_links follow the crawl they depend on.
    "domain_intel": 12 * HOUR,
    "js_mine": 24 * HOUR,
    "broken_links": 24 * HOUR,
    "tls": 24 * HOUR,
    "uncover": 24 * HOUR,
    "service_scan": 24 * HOUR,
    "cloud_buckets": 24 * HOUR,
    "nuclei_watch": 12 * HOUR,
    "dork": 24 * HOUR,
    # Attacker-coverage wave. api_surface/http_misconfig follow the probe they depend
    # on; supply_chain follows js_mine; typosquat is pure third-party DNS, so it is
    # cheap for us but noisy for resolvers — daily is plenty.
    "api_surface": 24 * HOUR,
    "http_misconfig": 24 * HOUR,
    "supply_chain": 24 * HOUR,
    "typosquat": 24 * HOUR,
    "reverse_dns": 24 * HOUR,
    "param_discovery": 24 * HOUR,
    "cloud_assets": 12 * HOUR,
}

#: Pipelines a user is allowed to set a custom cadence for.
CONFIGURABLE_PIPELINES: frozenset[str] = frozenset(DEFAULT_CADENCE_SECONDS)

#: Politeness floor — a custom cadence can never scan faster than this, whatever a
#: user enters (§3.8 continuous-scanning politeness).
MIN_INTERVAL_SECONDS: int = 5 * MINUTE

#: Cadences that contact nothing external.
NON_SCANNING: frozenset[str] = frozenset({"notify"})


def sanitize_overrides(overrides: dict | None, *, floor: int | None = None) -> dict[str, int]:
    """Keep only known pipelines with a sane positive interval, floored by MIN_INTERVAL_SECONDS."""
    out: dict[str, int] = {}
    for key, val in (overrides or {}).items():
        if key not in CONFIGURABLE_PIPELINES:
            continue
        try:
            seconds = int(val)
        except (TypeError, ValueError):
            continue
        if seconds <= 0:
            continue
        low = 0 if key in NON_SCANNING else max(MIN_INTERVAL_SECONDS, floor or 0)
        out[key] = max(seconds, low)
    return out


def effective_cadence(
    program_overrides: dict | None = None,
    tenant_defaults: dict | None = None,
    *,
    floor: int | None = None,
) -> dict[str, int]:
    """Resolve the cadence a program actually runs on."""
    merged = {
        k: (v if k in NON_SCANNING else max(v, floor or 0))
        for k, v in DEFAULT_CADENCE_SECONDS.items()
    }
    merged.update(sanitize_overrides(tenant_defaults, floor=floor))
    merged.update(sanitize_overrides(program_overrides, floor=floor))
    return merged


def is_due(last_run: datetime | None, now: datetime, interval_seconds: int) -> bool:
    """True if a pipeline that last ran at *last_run* is due again at *now*.

    Never-run (``last_run is None``) is always due — a brand-new program gets
    scanned immediately.
    """
    if last_run is None:
        return True
    return (now - last_run).total_seconds() >= interval_seconds


def next_due(last_run: datetime | None, interval_seconds: int) -> datetime | None:
    """When a pipeline that last ran at *last_run* is next due. ``None`` == due now
    (never run), which the UI renders as a pending/imminent scan."""
    if last_run is None:
        return None
    return last_run + timedelta(seconds=interval_seconds)
