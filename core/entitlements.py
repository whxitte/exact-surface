"""Process-wide license runtime holder + refresh (wires :mod:`core.license` to the app).

The evaluated :class:`~core.license.LicenseState` is cached in-process and consulted by
the enforcement guard on every request (cheap — no DB/crypto per request). It is
(re)computed at startup and on an interval by :func:`refresh`, which also advances the
clock high-water-mark and, if configured, pulls a renewed token from the license server.

Both the API and the worker hold their own copy — each reads the same env/file token,
the same public key, and the same Mongo high-water-mark, so they agree on the state.
Enforcement is applied where the value is produced (scan routes, scheduler, dispatch).
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from core.config import get_settings
from core.license import LicenseError, LicenseState, LicenseStatus, evaluate, verify_license
from core.logging import logger

_state: LicenseState | None = None
_last_refresh_monotonic: float = 0.0


def enforcement_active() -> bool:
    """Whether licence enforcement is on.

    A release image enforces unconditionally — see ``core.build_info``. The settings
    flag only has effect in a source checkout, so a customer cannot disable their own
    subscription with ``-e EXACTSURFACE_LICENSE_ENFORCED=false``.
    """
    from core.build_info import licence_enforced

    return licence_enforced(get_settings().license_enforced)


def current() -> LicenseState:
    """The cached license state. Before the first refresh it fails closed: read-only when
    enforcement is on, full function when off (dev/tests)."""
    if _state is not None:
        return _state
    return evaluate(None, now=datetime.now(UTC), enforced=enforcement_active())


def set_state(state: LicenseState | None) -> None:
    """Override the cached state (tests)."""
    global _state
    _state = state


def _load_token(settings: Any, stored: str | None) -> str | None:
    """Precedence: an online-refreshed token (stored) → env token → license file."""
    if stored:
        return stored.strip()
    if settings.license_token:
        return settings.license_token.strip()
    if settings.license_file:
        try:
            return Path(settings.license_file).read_text(encoding="utf-8").strip()
        except OSError as exc:
            logger.warning("license file unreadable ({}): {}", settings.license_file, exc)
    return None


async def refresh(mongo: Any, *, now: datetime | None = None) -> LicenseState:
    """Recompute and cache the license state. Idempotent and safe to call often."""
    global _state, _last_refresh_monotonic
    settings = get_settings()
    now = now or datetime.now(UTC)

    if not enforcement_active():
        _state = evaluate(None, now=now, enforced=False)
        _last_refresh_monotonic = time.monotonic()
        return _state

    from db.license_state import LicenseStateRepo

    repo = LicenseStateRepo.from_mongo(mongo)
    # Advance and read the clock high-water-mark (rollback detection input).
    clock_floor = await repo.bump_clock(now)
    stored = await repo.stored_token()
    token = _load_token(settings, stored)

    # Hybrid model: if an online-refresh endpoint is configured, best-effort pull a
    # renewed token (a paid renewal takes effect without a redeploy). Offline instances
    # leave license_refresh_url unset and rely purely on the signed token + grace.
    if settings.license_refresh_url and settings.license_public_key:
        refreshed = await _online_refresh(settings, token)
        if refreshed is not None:
            await repo.save_token(refreshed)
            token = refreshed

    entitlements = None
    error: LicenseError | None = None
    if token and settings.license_public_key:
        try:
            entitlements = verify_license(token, settings.license_public_key)
        except LicenseError as exc:
            error = exc
    elif token and not settings.license_public_key:
        error = LicenseError("no license public key configured on this instance")

    _state = evaluate(entitlements, now=now, clock_floor=clock_floor, error=error, enforced=True)
    _last_refresh_monotonic = time.monotonic()
    if _state.status not in (LicenseStatus.ACTIVE, LicenseStatus.UNLICENSED):
        logger.warning("license state: {} — {}", _state.status.value, _state.reason)
    elif _state.entitlements is not None:
        # Success was silent, which made a misconfigured licence hard to tell apart from
        # a working one: both produced no output. Say once, at startup, exactly which
        # licence this instance is running -- the first question any support case asks.
        ent = _state.entitlements
        logger.info(
            "license active: {} ({}), {} domain(s), expires {}",
            ent.customer_name,
            ent.plan.value,
            "unlimited" if ent.max_domains is None else ent.max_domains,
            ent.expires_at.date().isoformat(),
        )
    return _state


async def _online_refresh(settings: Any, current_token: str | None) -> str | None:
    """Ask the configured license server for a renewed token. Best-effort and safe: any
    failure (offline, timeout, bad response) returns None and the offline token stands.

    Contract — the license server (your infra) receives::

        POST {license_refresh_url}
        { "token": "<current license token or null>" }

    and returns ``{"token": "<a freshly-signed license>"}`` (or 4xx to decline). The
    returned token is verified against the embedded public key before it is trusted, so a
    hostile/misconfigured endpoint cannot inject entitlements — only a token you signed is
    ever accepted."""
    try:
        import aiohttp

        async with aiohttp.ClientSession() as session:
            async with session.post(
                settings.license_refresh_url,
                json={"token": current_token},
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status != 200:
                    return None
                data = await resp.json()
        new_token = (data or {}).get("token")
        if not new_token or new_token == current_token:
            return None
        # Only trust a token that verifies against OUR public key.
        verify_license(new_token, settings.license_public_key)
        logger.info("license refreshed from license server")
        return new_token
    except Exception as exc:  # noqa: BLE001 - refresh must never break the instance
        logger.debug("online license refresh skipped: {}", exc)
        return None


def watermark() -> str:
    """A traceable per-deployment tag — ``<customer_id>:<build_id>`` — stamped on
    exported reports and a response header, so a leaked instance's output can be traced
    back to the licensee. Falls back to ``unlicensed`` when no license is present."""
    st = current()
    cid = st.entitlements.customer_id if st.entitlements else "unlicensed"
    return f"{cid}:{get_settings().build_id}"


def summary() -> dict:
    """A JSON-safe snapshot of the license state for the UI (banner + settings)."""
    st = current()
    ent = st.entitlements
    return {
        "status": st.status.value,
        "read_only": st.read_only,
        "reason": st.reason,
        "enforced": enforcement_active(),
        "customer_name": ent.customer_name if ent else None,
        "plan": ent.plan.value if ent else None,
        "max_domains": ent.max_domains if ent else None,
        "expires_at": ent.expires_at.isoformat() if ent else None,
        "grace_ends_at": st.hard_expiry.isoformat() if st.hard_expiry else None,
    }


async def ensure_fresh(mongo: Any, *, max_age_seconds: float | None = None) -> LicenseState:
    """Refresh only if the cache is older than the check interval (worker-side use, so a
    long-lived worker still notices an expiry/renewal without a background task)."""
    settings = get_settings()
    max_age = (
        max_age_seconds if max_age_seconds is not None else settings.license_check_interval_seconds
    )
    if _state is None or (time.monotonic() - _last_refresh_monotonic) > max_age:
        return await refresh(mongo)
    return _state
