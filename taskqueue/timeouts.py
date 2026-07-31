"""Per-phase time limits (§continuous engine, configurable).

Each pipeline stage has a max runtime. nuclei (the ``scan`` stage) is the slow one
— it can legitimately run for an hour on a big URL set — so users need to bound it
per program. Resolved the same way as cadence: built-in defaults ← tenant defaults
← program overrides (most specific wins), with a floor and ceiling enforced so a
value entered in the UI can never make a stage hang forever or die instantly.

The stage is killed at its budget; tools that support partial results (nuclei)
keep what they found so far, so a timeout bounds the stage rather than failing it.
"""

from __future__ import annotations

MINUTE = 60
HOUR = 60 * MINUTE

#: stage -> max runtime seconds. Covers every full-pipeline stage (14).
DEFAULT_TIMEOUTS_SECONDS: dict[str, int] = {
    "domain_intel": 3 * MINUTE,  # DNS + one registry lookup
    "ingest": 5 * MINUTE,
    "uncover": 5 * MINUTE,
    "probe": 5 * MINUTE,
    "tls": 5 * MINUTE,
    "takeover": 5 * MINUTE,
    "crawl": 10 * MINUTE,
    "content_discovery": 10 * MINUTE,
    "js_mine": 10 * MINUTE,  # fetch + parse up to 150 bundles
    "broken_links": 10 * MINUTE,  # DNS + status checks on outbound links
    "port_scan": 10 * MINUTE,
    "service_scan": 10 * MINUTE,
    "scan": 60 * MINUTE,  # nuclei — the slow one
    "secrets": 10 * MINUTE,
    "cve_watch": 2 * MINUTE,
    "github_osint": 5 * MINUTE,
    "cloud_buckets": 5 * MINUTE,  # ~45 bucket probes, bounded fan-out
    "nuclei_watch": 2 * MINUTE,  # list templates + set diff; no target contact
    "dork": 5 * MINUTE,
    "api_surface": 15 * MINUTE,  # ~25 requests per origin, bounded fan-out
    "http_misconfig": 10 * MINUTE,
    "supply_chain": 10 * MINUTE,  # refetch a few bundles + one registry HEAD each
    "typosquat": 10 * MINUTE,  # two batched dnsx calls over ~600 names
    "reverse_dns": 15 * MINUTE,  # up to 8192 PTR lookups in one dnsx call
    "param_discovery": 20 * MINUTE,  # batched binary search over 60 URLs
    "correlate": 2 * MINUTE,
    "notify": 2 * MINUTE,
}

#: which stages a user may set a custom time limit for.
CONFIGURABLE_STAGES: frozenset[str] = frozenset(DEFAULT_TIMEOUTS_SECONDS)

MIN_TIMEOUT_SECONDS: int = 30
MAX_TIMEOUT_SECONDS: int = 6 * HOUR

#: headroom added to a stage's tool budget before the hard wait_for ceiling fires,
#: so a tool's own (graceful, partial-result-keeping) timeout triggers first.
STAGE_MARGIN_SECONDS: int = 2 * MINUTE


def sanitize_timeout_overrides(overrides: dict | None) -> dict[str, int]:
    """Keep only known stages with an int in [MIN, MAX]; clamp out-of-range values."""
    out: dict[str, int] = {}
    for key, val in (overrides or {}).items():
        if key not in CONFIGURABLE_STAGES:
            continue
        try:
            seconds = int(val)
        except (TypeError, ValueError):
            continue
        out[key] = max(MIN_TIMEOUT_SECONDS, min(seconds, MAX_TIMEOUT_SECONDS))
    return out


def effective_timeouts(
    program_overrides: dict | None = None, tenant_defaults: dict | None = None
) -> dict[str, int]:
    """Resolve each stage's max runtime: built-ins ← tenant defaults ← program."""
    merged = dict(DEFAULT_TIMEOUTS_SECONDS)
    merged.update(sanitize_timeout_overrides(tenant_defaults))
    merged.update(sanitize_timeout_overrides(program_overrides))
    return merged
