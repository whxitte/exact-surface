"""Global politeness rate limiter (§3.8b).

Scanning shared cloud infrastructure too fast gets abuse reports and, ultimately,
the platform's cloud account terminated. This limiter enforces a hard ceiling on
how fast ExactSurface contacts any single target, *regardless of how many concurrent
jobs touch it*, by keying the token bucket on ``(target-ip, asn)``.

The algorithm is a standard token bucket:

* a bucket holds up to ``burst`` tokens and refills at ``rate`` tokens/second;
* each network op tries to ``take(1)``; with no token available the store reports
  refusal, and it is the caller's choice whether to wait (``acquire``, what scan
  traffic does) or shed the op (``allow``/``require``).

Two backends implement the same interface: :class:`InMemoryBucketStore` (used in
tests and single-process dev) and :class:`RedisBucketStore` (shared across the
worker fleet in production). The bucket math lives in one place so both backends
behave identically. :class:`DegradingBucketStore` wraps the Redis one so a Redis
outage cannot stop scanning *or* silently lift the ceiling (ADR-0012).

**Scope of this limiter.** It governs *in-process* HTTP that ExactSurface makes to a
customer's targets — today the takeover probe and the secret fetcher. It cannot
govern a subprocess: naabu, httpx, katana, feroxbuster and nuclei send their own
packets and are capped by a derived ``-rate``/``-rl`` flag instead (ADR-0009).
Adding an in-process request to a target without pacing it through here re-opens
the AUP hole this exists to close.

Use :meth:`PolitenessLimiter.acquire` for scan traffic: politeness means the scan
is *slowed*, not that URLs are silently dropped from coverage. ``allow``/``require``
are for callers that genuinely want to shed load rather than wait.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Protocol

from core.errors import RateLimited
from core.logging import logger
from core.metrics import REGISTRY


@dataclass(frozen=True)
class RateLimit:
    """A rate ceiling: ``rate`` sustained tokens/sec with a ``burst`` cap."""

    rate: float
    burst: float

    @classmethod
    def per_second(cls, n: float) -> RateLimit:
        return cls(rate=float(n), burst=float(n))


#: Absolute ceiling on a scanner subprocess's aggregate packet rate, however many
#: targets it is given. Per-target politeness is the spec's requirement (§3.8b),
#: but our own egress still needs a hard stop.
SUBPROCESS_RATE_CEILING = 1000


def subprocess_rate_for(
    host_count: int, per_target_cap: float, *, ceiling: int = SUBPROCESS_RATE_CEILING
) -> int:
    """Aggregate packets/sec to give a scanner subprocess (naabu) so that the
    **per-target** rate stays within the politeness cap (§3.8b).

    The token-bucket limiter cannot govern a subprocess — naabu sends its own
    packets — so the ceiling has to be handed to the tool up front. naabu's
    ``-rate`` is process-wide and spread across its targets, so N targets at
    ``cap`` each means an aggregate of ``cap * N``, clamped to *ceiling*.
    """
    n = max(1, host_count)
    return max(1, min(ceiling, int(per_target_cap * n)))


@dataclass(frozen=True)
class SubprocessRate:
    """What a scanner subprocess was told, and what that means per target."""

    tool: str
    aggregate: int  #: value handed to the tool's rate flag (process-wide)
    per_target: float  #: derived per-target rate — must stay <= cap
    cap: float  #: the configured §3.8b ceiling

    @property
    def within_cap(self) -> bool:
        return self.per_target <= self.cap


def derive_subprocess_rate(
    host_count: int, per_target_cap: float, *, tool: str, ceiling: int = SUBPROCESS_RATE_CEILING
) -> SubprocessRate:
    """Derive a scanner subprocess's rate flag AND publish it (§3.8b, ADR-0013).

    Every tool that sends its own packets needs this: the token bucket in this
    process cannot see their traffic, so the ceiling has to be handed over up front.
    naabu was capped this way first (ADR-0009); httpx, katana, nuclei, feroxbuster
    and ffuf were not, and defaulted to 150 rps or unlimited.

    Publishing here rather than at each call site is deliberate — deriving the rate
    and reporting it become one act, so a tool cannot be capped-but-invisible (or,
    worse, look reported while running uncapped).
    """
    aggregate = subprocess_rate_for(host_count, per_target_cap, ceiling=ceiling)
    rate = SubprocessRate(
        tool=tool,
        aggregate=aggregate,
        per_target=aggregate / max(1, host_count),
        cap=per_target_cap,
    )
    REGISTRY.set(
        "exactsurface_politeness_rate_limit_pps",
        per_target_cap,
        help="Configured max packets/requests per second per target IP (§3.8b)",
    )
    REGISTRY.set(
        "exactsurface_subprocess_rate_pps",
        float(aggregate),
        help="Aggregate rate handed to a scanner subprocess's rate flag",
        tool=tool,
    )
    REGISTRY.set(
        "exactsurface_subprocess_per_target_pps",
        rate.per_target,
        help="Derived per-target rate for a scanner subprocess; must stay <= the cap (§3.8b)",
        tool=tool,
    )
    return rate


def build_limiter(settings, store=None, *, redis=None) -> PolitenessLimiter:
    """Construct a process's politeness limiter from settings.

    **Pass ``redis`` in any deployment.** The ceiling in §3.8b is per *target*, not
    per process: with a local store each worker gets its own bucket and N replicas
    emit N× the configured rate at a third party's host. This lived in
    ``taskqueue.worker`` and defaulted to the in-memory store, and the worker never
    passed anything else — so the shared ceiling was never enforced anywhere
    (ADR-0012). It sits here now so it is importable without arq, and therefore
    testable at all.

    Without ``redis`` (or an explicit ``store``) it returns a local limiter, because
    single-process dev and the tests genuinely have no fleet to share with. That is
    a *dev* default, not a deployment one — the worker refuses it in prod.
    """
    limit = RateLimit.per_second(settings.global_rate_per_target)
    if store is None:
        store = (
            DegradingBucketStore(
                RedisBucketStore(redis),
                InMemoryBucketStore(),
                fleet_size=settings.worker_fleet_size,
            )
            if redis is not None
            else InMemoryBucketStore()
        )
    return PolitenessLimiter(store, default_limit=limit)


def throttled_fetch(fetch, limiter: PolitenessLimiter, *, host_of=None):
    """Wrap an async ``fetch(url, ...)`` so every request is paced by *limiter*.

    The pipelines already inject their fetch function (that is how they stay
    offline-testable), so wrapping at the injection point makes the ceiling apply
    without every module having to remember to ask for permission — the kind of
    "remember to wire it" contract that silently rots.

    Keyed on the URL **host**, not the resolved IP. Two hosts on one IP therefore
    get a bucket each, which under-throttles shared infrastructure relative to a
    strict per-IP reading of §3.8b. It is the honest trade here: resolving inside
    the wrapper would add a DNS round trip per request and the callers already hold
    scope-checked hostnames. Port scanning, where per-IP matters most, is capped by
    naabu's derived ``-rate`` (ADR-0009) rather than by this.
    """
    get_host = host_of or _host_of

    async def _fetch(url, *args, **kwargs):
        await limiter.acquire(get_host(url))
        return await fetch(url, *args, **kwargs)

    return _fetch


def _host_of(url: str) -> str:
    """Bucket key for a URL. Falls back to the raw string for a bare hostname."""
    from urllib.parse import urlsplit

    return urlsplit(url).hostname or url


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

    **The clock is Redis's, not the caller's.** ``take()`` ignores its ``now``
    argument. A shared bucket needs a shared clock, and neither obvious client-side
    option works: ``time.monotonic()`` has a per-process epoch, so timestamps from
    different workers are not comparable at all, and ``time.time()`` is comparable
    but skewed — a worker whose clock runs 5s fast computes 5s of refill on its
    first call and bursts straight through the ceiling. ``redis.call('TIME')`` is
    one authoritative clock for the whole fleet with no skew by construction.
    (Non-deterministic commands are fine here: Redis has replicated scripts by
    effect since 5.0, and the compose stack pins redis 7.)
    """

    _LUA = """
    local tokens_key = KEYS[1]
    local ts_key = KEYS[2]
    local rate = tonumber(ARGV[1])
    local burst = tonumber(ARGV[2])
    local cost = tonumber(ARGV[3])
    local t = redis.call('TIME')
    local now = tonumber(t[1]) + tonumber(t[2]) / 1000000
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

    def __init__(self, redis, namespace: str = "exactsurface:rl") -> None:
        self._redis = redis
        self._ns = namespace
        self._sha: str | None = None

    async def _script(self) -> str:
        if self._sha is None:
            self._sha = await self._redis.script_load(self._LUA)
        return self._sha

    async def take(self, key: str, limit: RateLimit, cost: float, now: float) -> bool:
        """``now`` is accepted for the :class:`BucketStore` protocol and ignored —
        see the class docstring: the script reads Redis's clock instead."""
        sha = await self._script()
        result = await self._redis.evalsha(
            sha,
            2,
            f"{self._ns}:{key}:t",
            f"{self._ns}:{key}:ts",
            limit.rate,
            limit.burst,
            cost,
        )
        return bool(int(result))


class DegradingBucketStore:
    """Wraps a shared store (Redis) with a safe local fallback (§7, ADR-0012).

    The failure to avoid is subtle. If Redis is down there are three options and
    two of them are wrong:

    * **Fail open** (allow everything) — silently removes the ceiling. A Redis blip
      becomes an AUP breach against a third party. Never.
    * **Fail closed** (deny everything) — safe, but a Redis blip stops all scanning,
      which is the outage §7's "graceful degradation" exists to prevent.
    * **Degrade to a local bucket at a divided rate** — what this does.

    The division is the whole point. A local bucket is *per process*, so N workers
    each running a local bucket at the full rate would emit N× the ceiling at the
    target. Dividing by ``fleet_size`` means that even if every worker degrades at
    once, the aggregate stays within the configured cap. It scans slower than
    necessary when only one worker has degraded — the right way to be wrong.

    ``fleet_size`` must be **>= the real worker count**, or the guarantee is void;
    see ``Settings.worker_fleet_size``.
    """

    def __init__(self, primary: BucketStore, fallback: BucketStore, *, fleet_size: int) -> None:
        if fleet_size < 1:
            raise ValueError("fleet_size must be >= 1")
        self._primary = primary
        self._fallback = fallback
        self._fleet_size = fleet_size
        self._degraded = False

    @property
    def degraded(self) -> bool:
        return self._degraded

    def _local_limit(self, limit: RateLimit) -> RateLimit:
        """This process's share of the global ceiling while the shared store is down."""
        return RateLimit(
            rate=limit.rate / self._fleet_size,
            burst=max(1.0, limit.burst / self._fleet_size),
        )

    async def take(self, key: str, limit: RateLimit, cost: float, now: float) -> bool:
        try:
            allowed = await self._primary.take(key, limit, cost, now)
        except Exception as exc:  # noqa: BLE001 - ANY primary failure must degrade, not raise
            self._note_degraded(exc)
            return await self._fallback.take(key, self._local_limit(limit), cost, now)
        self._note_recovered()
        return allowed

    def _note_degraded(self, exc: Exception) -> None:
        if not self._degraded:  # log the transition, not every call
            logger.warning(
                "politeness limiter degraded to a local bucket at 1/{} rate — shared "
                "store unavailable: {}",
                self._fleet_size,
                exc,
            )
        self._degraded = True
        REGISTRY.set(
            "exactsurface_politeness_store_degraded",
            1.0,
            help="1 while the shared rate-limit store is unreachable and this process "
            "is enforcing its divided local share of the ceiling (§7).",
        )

    def _note_recovered(self) -> None:
        if self._degraded:
            logger.info("politeness limiter recovered — shared store reachable again")
        self._degraded = False
        REGISTRY.set("exactsurface_politeness_store_degraded", 0.0)


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
        eff = limit or self._default
        ok = await self._store.take(self.target_key(ip, asn), eff, cost, time.monotonic())
        # Aggregate only — a per-target label would mint a time series per scanned
        # IP and blow up cardinality. The ratio of throttled:allowed is what tells
        # an operator the ceiling is doing work.
        REGISTRY.inc(
            "exactsurface_politeness_decisions_total",
            help="Politeness limiter decisions (§3.8b)",
            decision="allowed" if ok else "throttled",
        )
        REGISTRY.set(
            "exactsurface_politeness_rate_limit_pps",
            eff.rate,
            help="Configured max packets/requests per second per target IP (§3.8b)",
        )
        return ok

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

    async def acquire(
        self,
        ip: str,
        asn: str | int | None = None,
        cost: float = 1.0,
        limit: RateLimit | None = None,
        *,
        max_wait: float = 60.0,
        sleep=asyncio.sleep,
    ) -> float:
        """Wait until the target's budget allows this op. Returns seconds waited.

        This is the primitive scan traffic should use. ``allow()`` returning False
        means "drop it", which for a scanner silently removes a URL from coverage
        and reports a clean result — politeness must cost *time*, not findings.

        ``max_wait`` bounds the wait so a wedged bucket cannot hang a stage past its
        timeout; on expiry it proceeds anyway rather than dropping the request. That
        is safe because the ceiling is still enforced for every *other* caller and
        the overshoot is one request, whereas silently skipping targets would be a
        correctness bug an operator cannot see. ``sleep`` is injectable so tests do
        not spend real seconds.
        """
        eff = limit or self._default
        waited = 0.0
        # One token's worth of time; never busy-spin, never sleep longer than needed.
        step = min(max(cost / max(eff.rate, 1e-9), 0.001), 1.0)
        while True:
            if await self.allow(ip, asn, cost, eff):
                return waited
            if waited >= max_wait:
                logger.warning(
                    "politeness wait for {} exceeded {}s — proceeding; the target may "
                    "be over-contended or the bucket wedged",
                    self.target_key(ip, asn),
                    max_wait,
                )
                return waited
            await sleep(step)
            waited += step
