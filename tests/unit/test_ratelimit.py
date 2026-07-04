from __future__ import annotations

import pytest

from core.errors import RateLimited
from core.ratelimit import (
    InMemoryBucketStore,
    PolitenessLimiter,
    RateLimit,
    _refill,
)


async def test_token_bucket_allows_burst_then_blocks():
    store = InMemoryBucketStore()
    limit = RateLimit(rate=1.0, burst=3.0)
    now = 1000.0
    # 3 tokens available at burst
    assert await store.take("t", limit, 1, now)
    assert await store.take("t", limit, 1, now)
    assert await store.take("t", limit, 1, now)
    # 4th is refused (no refill yet)
    assert not await store.take("t", limit, 1, now)


async def test_token_bucket_refills_over_time():
    store = InMemoryBucketStore()
    limit = RateLimit(rate=1.0, burst=3.0)
    for _ in range(3):
        await store.take("t", limit, 1, 1000.0)
    assert not await store.take("t", limit, 1, 1000.0)
    # 2 seconds later → 2 tokens back
    assert await store.take("t", limit, 1, 1002.0)
    assert await store.take("t", limit, 1, 1002.0)
    assert not await store.take("t", limit, 1, 1002.0)


def test_refill_never_exceeds_burst():
    tokens, ts = _refill(0.0, 0.0, 10_000.0, RateLimit(rate=5.0, burst=10.0))
    assert tokens == 10.0


async def test_keys_are_independent():
    store = InMemoryBucketStore()
    limit = RateLimit(rate=1.0, burst=1.0)
    assert await store.take("ip-a", limit, 1, 0.0)
    assert await store.take("ip-b", limit, 1, 0.0)  # different target, own budget
    assert not await store.take("ip-a", limit, 1, 0.0)


async def test_limiter_require_raises_when_exhausted():
    class DenyStore:
        async def take(self, *_a, **_k):
            return False

    limiter = PolitenessLimiter(DenyStore(), RateLimit.per_second(10))
    with pytest.raises(RateLimited):
        await limiter.require("45.55.1.1", asn=14061)


def test_target_key_includes_asn():
    assert PolitenessLimiter.target_key("1.2.3.4", 14061) == "1.2.3.4|asn:14061"
    assert PolitenessLimiter.target_key("1.2.3.4") == "1.2.3.4"
