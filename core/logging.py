"""Loguru setup with tenant/scan context (§3.4, §11 — never ``print``).

``tenant_id`` and ``scan_id`` are carried in :mod:`contextvars` so every log line
emitted anywhere in an async task is automatically tagged with the tenant it
belongs to — essential for multi-tenant debugging and for proving isolation in
audit trails. Bind them with :func:`bind_context` (usually once per job/request).
"""

from __future__ import annotations

import contextvars
import sys
from collections.abc import Iterator
from contextlib import contextmanager

from loguru import logger

_tenant_id: contextvars.ContextVar[str] = contextvars.ContextVar("tenant_id", default="-")
_scan_id: contextvars.ContextVar[str] = contextvars.ContextVar("scan_id", default="-")


def _patch(record: dict) -> None:
    record["extra"].setdefault("tenant_id", _tenant_id.get())
    record["extra"].setdefault("scan_id", _scan_id.get())


def configure_logging(level: str = "INFO", json_logs: bool = False) -> None:
    """Install the process-wide log sink. Call once at startup."""
    logger.remove()
    logger.configure(patcher=_patch)
    if json_logs:
        logger.add(sys.stderr, level=level, serialize=True, backtrace=False, diagnose=False)
    else:
        fmt = (
            "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level> | "
            "<cyan>t={extra[tenant_id]}</cyan> <cyan>s={extra[scan_id]}</cyan> | "
            "<level>{message}</level>"
        )
        logger.add(sys.stderr, level=level, format=fmt, backtrace=False, diagnose=False)


@contextmanager
def bind_context(tenant_id: str = "-", scan_id: str = "-") -> Iterator[None]:
    """Bind tenant/scan ids for the duration of a request or job."""
    t = _tenant_id.set(tenant_id)
    s = _scan_id.set(scan_id)
    try:
        yield
    finally:
        _tenant_id.reset(t)
        _scan_id.reset(s)


__all__ = ["logger", "configure_logging", "bind_context"]
