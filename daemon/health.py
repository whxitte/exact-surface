"""Pre-flight validation (§4, §7 Phase A exit criteria).

Validates config, the scope-engine feeds, every required external binary, and the
datastore + redis connections. Designed to degrade gracefully: a missing driver or
an unreachable DB is reported as a failed check, never an import crash — so
``--dry-run`` works on a bare dev box while a real boot fails fast on real gaps.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass

from core.config import get_settings
from core.errors import ExactSurfaceError
from core.scope import default_engine
from modules.registry import required_binaries


@dataclass
class Check:
    name: str
    ok: bool
    detail: str


@dataclass
class HealthReport:
    checks: list[Check]

    @property
    def ok(self) -> bool:
        return all(c.ok for c in self.checks)

    def critical_ok(self, critical: set[str]) -> bool:
        """True if every check whose name is in *critical* passed."""
        return all(c.ok for c in self.checks if c.name in critical)


def _check_config() -> Check:
    try:
        s = get_settings()
        s.assert_prod_safe()
        return Check("config", True, f"env={s.env} db={s.mongo_db}")
    except ExactSurfaceError as exc:
        return Check("config", False, str(exc))


def _check_scope_feeds() -> Check:
    try:
        eng = default_engine()
        total = sum(len(v) for v in eng._ranges.values())
        return Check("scope_feeds", total > 0, f"{total} CDN/cloud ranges loaded")
    except Exception as exc:  # noqa: BLE001 - surface any feed error as a failed check
        return Check("scope_feeds", False, str(exc))


def _check_binaries() -> list[Check]:
    checks: list[Check] = []
    for binary in required_binaries():
        path = shutil.which(binary)
        checks.append(Check(f"bin:{binary}", path is not None, path or "MISSING on PATH"))
    return checks


async def _check_mongo() -> Check:
    try:
        from db.mongo import get_mongo

        await get_mongo().ping()
        return Check("mongo", True, "ping ok")
    except Exception as exc:  # noqa: BLE001
        return Check("mongo", False, f"{type(exc).__name__}: {exc}")


async def _check_redis() -> Check:
    try:
        import redis.asyncio as aioredis  # type: ignore

        client = aioredis.from_url(get_settings().redis_uri)
        await client.ping()
        await client.aclose()
        return Check("redis", True, "ping ok")
    except Exception as exc:  # noqa: BLE001
        return Check("redis", False, f"{type(exc).__name__}: {exc}")


async def run_health_checks(check_services: bool = True) -> HealthReport:
    """Run all checks. Set ``check_services=False`` to skip DB/redis network I/O."""
    checks: list[Check] = [_check_config(), _check_scope_feeds(), *_check_binaries()]
    if check_services:
        checks.append(await _check_mongo())
        checks.append(await _check_redis())
    return HealthReport(checks)
