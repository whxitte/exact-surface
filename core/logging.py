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
_program_id: contextvars.ContextVar[str] = contextvars.ContextVar("program_id", default="-")
_pipeline: contextvars.ContextVar[str] = contextvars.ContextVar("pipeline", default="-")


def _patch(record: dict) -> None:
    record["extra"].setdefault("tenant_id", _tenant_id.get())
    record["extra"].setdefault("scan_id", _scan_id.get())
    record["extra"].setdefault("program_id", _program_id.get())
    record["extra"].setdefault("pipeline", _pipeline.get())


def configure_logging(level: str = "INFO", json_logs: bool = False) -> None:
    """Install the process-wide log sink. Call once at startup."""
    logger.remove()
    logger.configure(patcher=_patch)
    if json_logs:
        logger.add(sys.stderr, level=level, serialize=True, backtrace=False, diagnose=False)
    else:
        fmt = (
            "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level> | "
            "<cyan>t={extra[tenant_id]}</cyan> <cyan>p={extra[program_id]}</cyan> "
            "<cyan>s={extra[scan_id]}</cyan> <yellow>{extra[pipeline]}</yellow> | "
            "<level>{message}</level>"
        )
        logger.add(sys.stderr, level=level, format=fmt, backtrace=False, diagnose=False)


@contextmanager
def bind_context(
    tenant_id: str | None = None,
    scan_id: str | None = None,
    program_id: str | None = None,
    pipeline: str | None = None,
) -> Iterator[None]:
    """Bind ids for the duration of a request or job. Only fields you pass are
    overridden — so a nested ``bind_context(pipeline="ingest")`` keeps the
    tenant/scan/program set by the enclosing block.

    Every log line emitted within the block is tagged with these, so a scan's
    activity is fully attributable (multi-tenant debugging + the live log feed).
    """
    pairs = [
        (_tenant_id, tenant_id),
        (_scan_id, scan_id),
        (_program_id, program_id),
        (_pipeline, pipeline),
    ]
    tokens = [(var, var.set(val)) for var, val in pairs if val is not None]
    try:
        yield
    finally:
        for var, tok in reversed(tokens):
            var.reset(tok)


__all__ = ["logger", "configure_logging", "bind_context"]
