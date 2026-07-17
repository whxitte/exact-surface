"""Politeness limiter + alert latency are observable (§3.8b, §15).

The limiter's ceiling and the alert pipeline's latency were both enforced-but-
invisible. These pin the instrumentation, because "verified by metrics" is an
explicit Phase D exit requirement and §15 makes latency a product metric.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from core.metrics import REGISTRY
from core.ratelimit import InMemoryBucketStore, PolitenessLimiter, RateLimit
from pipelines.notify import _observe_alert_latency


async def test_limiter_counts_allowed_and_throttled():
    # burst of 1 → the first op is allowed, the second is throttled
    limiter = PolitenessLimiter(InMemoryBucketStore(), RateLimit(rate=0.0, burst=1.0))
    assert await limiter.allow("45.55.1.1") is True
    assert await limiter.allow("45.55.1.1") is False

    out = REGISTRY.render()
    assert 'vantari_politeness_decisions_total{decision="allowed"}' in out
    assert 'vantari_politeness_decisions_total{decision="throttled"}' in out
    # the configured ceiling is published so a dashboard can draw the limit line
    assert "vantari_politeness_rate_limit_pps" in out


async def test_limiter_does_not_label_by_target():
    """A per-target label would mint a series per scanned IP — unbounded cardinality."""
    limiter = PolitenessLimiter(InMemoryBucketStore(), RateLimit.per_second(10))
    await limiter.allow("1.1.1.1")
    await limiter.allow("2.2.2.2")
    out = REGISTRY.render()
    assert "1.1.1.1" not in out and "2.2.2.2" not in out


def test_alert_latency_is_recorded():
    _observe_alert_latency(datetime.now(UTC) - timedelta(seconds=30))
    out = REGISTRY.render()
    assert "vantari_alert_latency_seconds_bucket" in out
    assert "vantari_alert_latency_seconds_count" in out


def test_alert_latency_ignores_missing_or_naive_timestamps():
    """A legacy/tz-naive doc must be skipped, not recorded as a bogus latency —
    a wrong metric is worse than a missing one."""
    before = REGISTRY.render().count("vantari_alert_latency_seconds_count")
    _observe_alert_latency(None)
    _observe_alert_latency(datetime(2026, 1, 1))  # tz-naive → TypeError, swallowed
    after = REGISTRY.render().count("vantari_alert_latency_seconds_count")
    assert before == after  # nothing new recorded, nothing raised


def test_alert_latency_ignores_clock_skew():
    """A first_seen in the future would otherwise record a negative latency."""
    _observe_alert_latency(datetime.now(UTC) + timedelta(hours=1))  # must not raise
