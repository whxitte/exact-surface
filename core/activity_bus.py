"""Live activity bus — pushes ScanRun updates so the /activity websocket can
reflect a scan advancing in real time instead of only on the 3s poll.

Transport is Redis pub/sub (cross-process: the worker publishes, the API's
websocket subscribes). It is *purely additive*: if no bus is configured (tests,
or Redis unavailable), ``publish_run`` is a no-op and the frontend keeps polling.
Publishing must never break a scan, so every failure is swallowed at debug level.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Protocol

from core.logging import logger

CHANNEL_PREFIX = "vantari:activity:"


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
