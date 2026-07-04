"""Global politeness rate limiter (§3.8b).

Scanning shared cloud infrastructure too fast gets abuse reports and, ultimately,
the platform's cloud account terminated. This limiter enforces a hard ceiling on
how fast Vantari contacts any single target, *regardless of how many concurrent
jobs touch it*, by keying the token bucket on ``(target-ip, asn)``.

The algorithm is a standard token bucket:

* a bucket holds up to ``burst`` tokens and refills at ``rate`` tokens/second;
* each network op tries to ``take(1)``; if no token is available the op is
  refused (caller backs off / re-queues rather than blocking a worker).

Two backends implement the same interface: :class:`InMemoryBucketStore` (used in
tests and single-process dev) and :class:`RedisBucketStore` (shared across the
worker fleet in production). The bucket math lives in one place so both backends
behave identically.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Protocol

from core.errors import RateLimited


@dataclass(frozen=True)
class RateLimit:
    """A rate ceiling: ``rate`` sustained tokens/sec with a ``burst`` cap."""

    rate: float
    burst: float

    @classmethod
    def per_second(cls, n: float) -> RateLimit:
        return cls(rate=float(n), burst=float(n))


def _refill(tokens: float, last_ts: float, now: float, limit: RateLimit) -> tuple[float, float]:
    """Return (new_token_count, now) after refilling since ``last_ts``."""
    elapsed = max(0.0, now - last_ts)
    tokens = min(limit.burst, tokens + elapsed * limit.rate)
    return tokens, now


class BucketStore(Protocol):
    """Backend that persists (tokens, last_ts) per key and applies the bucket math."""

    async def take(self, key: str, limit: RateLimit, cost: float, now: float) -> bool: ...


class InMemoryBucketStore:
    """Process-local bucket store. Deterministic; ideal for tests and dev."""

    def __init__(self) -> None:
        self._buckets: dict[str, tuple[float, float]] = {}

    async def take(self, key: str, limit: RateLimit, cost: float, now: float) -> bool:
        tokens, last_ts = self._buckets.get(key, (limit.burst, now))
        tokens, last_ts = _refill(tokens, last_ts, now, limit)
        if tokens >= cost:
            tokens -= cost
            self._buckets[key] = (tokens, last_ts)
            return True
        self._buckets[key] = (tokens, last_ts)
        return False


class RedisBucketStore:
    """Redis-backed store shared across workers.

    Uses a small Lua script so refill + conditional decrement is atomic under
    concurrency (no read-modify-write race between workers). The redis client is
    injected so this module has no hard redis dependency and stays importable in
    environments without it.
    """

    _LUA = """
    local tokens_key = KEYS[1]
    local ts_key = KEYS[2]
    local rate = tonumber(ARGV[1])
    local burst = tonumber(ARGV[2])
    local now = tonumber(ARGV[3])
    local cost = tonumber(ARGV[4])
    local tokens = tonumber(redis.call('get', tokens_key))
    local last = tonumber(redis.call('get', ts_key))
    if tokens == nil then tokens = burst end
    if last == nil then last = now end
    local elapsed = now - last
    if elapsed < 0 then elapsed = 0 end
    tokens = math.min(burst, tokens + elapsed * rate)
    local allowed = 0
    if tokens >= cost then
        tokens = tokens - cost
        allowed = 1
    end
    redis.call('set', tokens_key, tokens, 'EX', 3600)
    redis.call('set', ts_key, now, 'EX', 3600)
    return allowed
    """

    def __init__(self, redis, namespace: str = "vantari:rl") -> None:
        self._redis = redis
        self._ns = namespace
        self._sha: str | None = None

    async def _script(self) -> str:
        if self._sha is None:
            self._sha = await self._redis.script_load(self._LUA)
        return self._sha

    async def take(self, key: str, limit: RateLimit, cost: float, now: float) -> bool:
        sha = await self._script()
        result = await self._redis.evalsha(
            sha,
            2,
            f"{self._ns}:{key}:t",
            f"{self._ns}:{key}:ts",
            limit.rate,
            limit.burst,
            now,
            cost,
        )
        return bool(int(result))


class PolitenessLimiter:
    """Enforces per-target rate ceilings using a pluggable :class:`BucketStore`."""

    def __init__(self, store: BucketStore, default_limit: RateLimit) -> None:
        self._store = store
        self._default = default_limit

    @staticmethod
    def target_key(ip: str, asn: str | int | None = None) -> str:
        """Bucket key for a target. ASN, when known, groups an org's IPs together."""
        return f"{ip}|asn:{asn}" if asn is not None else ip

    async def allow(
        self,
        ip: str,
        asn: str | int | None = None,
        cost: float = 1.0,
        limit: RateLimit | None = None,
    ) -> bool:
        """Return True and consume budget if the op is within the ceiling."""
        return await self._store.take(
            self.target_key(ip, asn), limit or self._default, cost, time.monotonic()
        )

    async def require(
        self,
        ip: str,
        asn: str | int | None = None,
        cost: float = 1.0,
        limit: RateLimit | None = None,
    ) -> None:
        """Raise :class:`RateLimited` if the op would exceed the ceiling."""
        eff = limit or self._default
        if not await self.allow(ip, asn, cost, eff):
            raise RateLimited(self.target_key(ip, asn), retry_after=cost / max(eff.rate, 1e-9))
