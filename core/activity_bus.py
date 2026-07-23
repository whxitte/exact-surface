"""Live activity bus — pushes ScanRun updates so the /activity websocket can
reflect a scan advancing in real time instead of only on the 3s poll.

Transport is Redis pub/sub (cross-process: the worker publishes, the API's
websocket subscribes). It is *purely additive*: if no bus is configured (tests,
or Redis unavailable), ``publish_run`` is a no-op and the frontend keeps polling.
Publishing must never break a scan, so every failure is swallowed at debug level.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime
from typing import Any, Protocol

from core.logging import logger

CHANNEL_PREFIX = "exactsurface:activity:"
LOG_KEY_PREFIX = "exactsurface:logs:"
LOG_MAX_LINES = 500  # keep the last N log lines per scan
LOG_TTL_SECONDS = 86400  # logs expire after a day


def channel_for(tenant_id: str) -> str:
    return f"{CHANNEL_PREFIX}{tenant_id}"


def _json_default(o: Any) -> str:
    return o.isoformat() if isinstance(o, datetime) else str(o)


class ActivityBus(Protocol):
    async def publish(self, tenant_id: str, run: dict) -> None: ...


_bus: ActivityBus | None = None


def set_bus(bus: ActivityBus | None) -> None:
    """Register (or clear) the process-wide bus. Called at API/worker startup."""
    global _bus
    _bus = bus


def get_bus() -> ActivityBus | None:
    return _bus


async def publish_run(tenant_id: str, run: dict) -> None:
    """Publish one ScanRun snapshot; no-op if no bus, never raises."""
    if _bus is None:
        return
    try:
        await _bus.publish(tenant_id, run)
    except Exception as exc:  # noqa: BLE001 - the bus must never break a scan
        logger.debug("activity publish failed: {}", exc)


class RedisActivityBus:
    """Redis pub/sub bus. ``redis`` is imported lazily so importing this module
    never requires the dependency (matches db/mongo, taskqueue)."""

    def __init__(self, redis: Any) -> None:
        self._r = redis

    @classmethod
    def connect(cls, redis_uri: str) -> RedisActivityBus:
        from redis.asyncio import from_url

        return cls(from_url(redis_uri, decode_responses=True))

    async def publish(self, tenant_id: str, run: dict) -> None:
        await self._r.publish(channel_for(tenant_id), json.dumps(run, default=_json_default))

    async def push_log(self, scan_id: str, line: str) -> None:
        """Append one log line to the capped per-scan list (best-effort, silent)."""
        key = f"{LOG_KEY_PREFIX}{scan_id}"
        try:
            await self._r.rpush(key, line)
            await self._r.ltrim(key, -LOG_MAX_LINES, -1)
            await self._r.expire(key, LOG_TTL_SECONDS)
        except Exception:  # noqa: BLE001, S110 - must not log here (would re-enter the sink)
            pass

    async def get_logs(self, scan_id: str, limit: int = LOG_MAX_LINES) -> list[str]:
        key = f"{LOG_KEY_PREFIX}{scan_id}"
        try:
            return await self._r.lrange(key, -limit, -1)
        except Exception as exc:  # noqa: BLE001
            logger.debug("get_logs failed: {}", exc)
            return []

    async def listen(self, tenant_id: str):
        """Async-iterate JSON run updates published for *tenant_id*."""
        pubsub = self._r.pubsub()
        await pubsub.subscribe(channel_for(tenant_id))
        try:
            async for message in pubsub.listen():
                if message.get("type") == "message":
                    yield json.loads(message["data"])
        finally:
            await pubsub.unsubscribe(channel_for(tenant_id))
            await pubsub.aclose()

    async def close(self) -> None:
        try:
            await self._r.aclose()
        except Exception as exc:  # noqa: BLE001 - shutdown is best-effort
            logger.debug("activity bus close skipped: {}", exc)


def format_log_line(record: Any) -> str:
    """Render a loguru record as one compact line for the live scan-log feed."""
    ts = record["time"].strftime("%H:%M:%S")
    level = record["level"].name
    pipeline = record["extra"].get("pipeline", "-")
    return f"{ts} {level:<7} [{pipeline}] {record['message']}"


_capture_installed = False


def install_scan_log_capture(min_level: str = "INFO") -> None:
    """Add a loguru sink that streams any log line bound to a scan_id into that
    scan's Redis log list, so the /activity UI can show what a scan is doing live.

    Idempotent; a no-op when no bus is set. Lines with no scan_id (API requests,
    the scheduler) are ignored — only per-scan work is captured.
    """
    global _capture_installed
    if _capture_installed:
        return

    def _sink(message: Any) -> None:
        record = message.record
        scan_id = record["extra"].get("scan_id", "-")
        if not scan_id or scan_id == "-":
            return
        bus = get_bus()
        if bus is None or not hasattr(bus, "push_log"):
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return  # no running loop → can't schedule the async push
        loop.create_task(bus.push_log(scan_id, format_log_line(record)))

    logger.add(_sink, level=min_level, format="{message}")
    _capture_installed = True
