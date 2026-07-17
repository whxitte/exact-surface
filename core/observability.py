"""Observability wiring: Sentry error reporting (§9 Phase G).

Sentry is optional and lazily imported — no DSN configured (or the SDK absent)
means it is silently skipped, never a startup failure. Prometheus metrics live in
``core/metrics.py`` and are instrumented at the call sites.
"""

from __future__ import annotations

from core.config import Settings, get_settings
from core.logging import logger


def init_sentry(settings: Settings | None = None) -> bool:
    """Initialise Sentry if a DSN is configured. Returns True if enabled."""
    settings = settings or get_settings()
    if settings.sentry_dsn is None:
        return False
    try:
        import sentry_sdk
    except ModuleNotFoundError:  # pragma: no cover - optional dependency
        logger.warning("sentry_sdk not installed; error reporting disabled")
        return False

    sentry_sdk.init(  # pragma: no cover - needs a real DSN
        dsn=settings.sentry_dsn.get_secret_value(),
        environment=settings.env,
        traces_sample_rate=0.1,
        send_default_pii=False,  # never ship customer data to Sentry
    )
    logger.info("sentry error reporting enabled (env={})", settings.env)
    return True
