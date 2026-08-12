"""Process-wide runtime status for self-hosted instances."""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Any

from core.license import LicenseState, evaluate

_state: LicenseState | None = None
_last_refresh_monotonic: float = 0.0


def enforcement_active() -> bool:
    """Always False — self-hosted product is completely free."""
    return False


def current() -> LicenseState:
    """The cached state — full function unconditionally."""
    if _state is not None:
        return _state
    return evaluate(None, now=datetime.now(UTC), enforced=False)


def set_state(state: LicenseState | None) -> None:
    """Override the cached state (tests)."""
    global _state
    _state = state


async def refresh(mongo: Any = None, *, now: datetime | None = None) -> LicenseState:
    """Recompute and cache the state. Always full function."""
    global _state, _last_refresh_monotonic
    now = now or datetime.now(UTC)
    _state = evaluate(None, now=now, enforced=False)
    _last_refresh_monotonic = time.monotonic()
    return _state


def summary() -> dict:
    """A JSON-safe snapshot of the state for the UI."""
    return {
        "status": "unlimited",
        "read_only": False,
        "reason": "Self-hosted edition — completely free for life with unlimited domains, modules, users and scans",
        "enforced": False,
        "customer_name": None,
        "plan": "free",
        "max_domains": None,
        "expires_at": None,
        "grace_ends_at": None,
    }


async def ensure_fresh(mongo: Any = None, *, max_age_seconds: float | None = None) -> LicenseState:
    """Ensure cached state is fresh."""
    if _state is None:
        return await refresh(mongo)
    return _state
