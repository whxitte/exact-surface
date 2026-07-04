"""MongoDB connection + index bootstrap (self-hosted first; Atlas optional).

Motor is imported lazily so this module (and therefore ``daemon.health`` and the
CLI) import cleanly in environments without the driver installed; ``connect()``
raises a clear error if it is genuinely needed and missing.

Every stateful collection gets, at minimum (§5a):
  * unique ``(tenant_id, fingerprint)`` — the idempotent upsert key
  * ``(tenant_id, program_id)`` — the dominant query
  * ``(tenant_id, is_new)`` — "new today"
  * ``(tenant_id, severity, first_seen)`` — triage dashboards (where applicable)
"""

from __future__ import annotations

from typing import Any

from core.config import Settings, get_settings
from core.errors import ConfigError
from core.logging import logger

# Index spec: (name, keys, options). keys is a list of (field, direction/1/-1).
ASC = 1
DESC = -1

_STATEFUL_BASE: list[tuple[str, list[tuple[str, int]], dict[str, Any]]] = [
    ("uniq_fp", [("tenant_id", ASC), ("fingerprint", ASC)], {"unique": True}),
    ("by_program", [("tenant_id", ASC), ("program_id", ASC)], {}),
    ("by_is_new", [("tenant_id", ASC), ("is_new", ASC)], {}),
    ("by_last_seen", [("tenant_id", ASC), ("last_seen", DESC)], {}),
]

_TRIAGE = ("by_severity", [("tenant_id", ASC), ("severity", ASC), ("first_seen", DESC)], {})

INDEXES: dict[str, list[tuple[str, list[tuple[str, int]], dict[str, Any]]]] = {
    "tenants": [("uniq_tenant", [("tenant_id", ASC)], {"unique": True})],
    "users": [
        ("uniq_email", [("email", ASC)], {"unique": True}),
        ("by_user", [("tenant_id", ASC), ("user_id", ASC)], {"unique": True}),
    ],
    "apikeys": [
        ("uniq_hash", [("key_hash", ASC)], {"unique": True}),
        ("by_key", [("tenant_id", ASC), ("key_id", ASC)], {"unique": True}),
    ],
    "programs": [
        ("uniq_program", [("tenant_id", ASC), ("program_id", ASC)], {"unique": True}),
        ("by_apex", [("tenant_id", ASC), ("apex_domain", ASC)], {}),
    ],
    "authorizations": [
        ("uniq_auth", [("tenant_id", ASC), ("program_id", ASC)], {"unique": True}),
    ],
    "assets": _STATEFUL_BASE,
    "endpoints": _STATEFUL_BASE,
    "ports": _STATEFUL_BASE,
    "findings": _STATEFUL_BASE + [_TRIAGE],
    "secrets": _STATEFUL_BASE + [_TRIAGE],
    "leaks": _STATEFUL_BASE,
    "cve_matches": _STATEFUL_BASE + [_TRIAGE],
    "deltas": [
        ("by_asset", [("tenant_id", ASC), ("asset_fingerprint", ASC)], {}),
        ("by_observed", [("tenant_id", ASC), ("observed_at", DESC)], {}),
    ],
    "scan_runs": [
        ("by_scan", [("tenant_id", ASC), ("scan_id", ASC)], {"unique": True}),
        ("by_program", [("tenant_id", ASC), ("program_id", ASC)], {}),
    ],
    "audit": [("by_ts", [("tenant_id", ASC), ("created_at", DESC)], {})],
}


class Mongo:
    """Thin async wrapper around a motor client + database handle."""

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()
        self._client: Any = None
        self._db: Any = None

    async def connect(self) -> None:
        try:
            from motor.motor_asyncio import AsyncIOMotorClient
        except ModuleNotFoundError as exc:  # pragma: no cover - env dependent
            raise ConfigError("motor is not installed; add 'motor' to run against MongoDB") from exc
        self._client = AsyncIOMotorClient(
            self._settings.mongo_uri, serverSelectionTimeoutMS=5000, tz_aware=True
        )
        self._db = self._client[self._settings.mongo_db]
        logger.info("connected to mongo db={}", self._settings.mongo_db)

    async def ping(self) -> bool:
        if self._client is None:
            await self.connect()
        await self._client.admin.command("ping")
        return True

    @property
    def db(self) -> Any:
        if self._db is None:
            raise ConfigError("Mongo.connect() must be called before use")
        return self._db

    def collection(self, name: str) -> Any:
        return self.db[name]

    async def ensure_indexes(self) -> int:
        """Create every declared index. Idempotent — safe to run on each boot."""
        from pymongo import IndexModel

        created = 0
        for coll_name, specs in INDEXES.items():
            models = [IndexModel(keys, name=name, **opts) for name, keys, opts in specs]
            if models:
                await self.db[coll_name].create_indexes(models)
                created += len(models)
        logger.info("ensured {} indexes across {} collections", created, len(INDEXES))
        return created

    async def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None
            self._db = None


_mongo: Mongo | None = None


def get_mongo() -> Mongo:
    """Process-wide Mongo handle (connect() still required before first use)."""
    global _mongo
    if _mongo is None:
        _mongo = Mongo()
    return _mongo
