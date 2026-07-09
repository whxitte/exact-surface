"""Effective-cadence resolution + politeness floor + next-due computation."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from taskqueue.cadence import (
    DEFAULT_CADENCE_SECONDS,
    MIN_INTERVAL_SECONDS,
    effective_cadence,
    next_due,
    sanitize_overrides,
)


def test_sanitize_drops_unknown_and_floors_interval():
    out = sanitize_overrides({"ingest": 10, "bogus": 60, "scan": "notint", "crawl": 3600})
    assert out["ingest"] == MIN_INTERVAL_SECONDS  # floored up from 10s
    assert out["crawl"] == 3600
    assert "bogus" not in out and "scan" not in out  # unknown / non-int dropped


def test_effective_cadence_program_overrides_tenant_overrides_default():
    eff = effective_cadence(
        program_overrides={"ingest": 3600},
        tenant_defaults={"ingest": 7200, "crawl": 12 * 3600},
    )
    assert eff["ingest"] == 3600  # program wins over tenant
    assert eff["crawl"] == 12 * 3600  # tenant wins over built-in
    assert eff["scan"] == DEFAULT_CADENCE_SECONDS["scan"]  # untouched default


def test_effective_cadence_empty_is_defaults():
    assert effective_cadence() == DEFAULT_CADENCE_SECONDS


def test_next_due():
    now = datetime(2026, 7, 4, 12, 0, tzinfo=UTC)
    assert next_due(None, 3600) is None  # never run → due now
    assert next_due(now, 3600) == now + timedelta(hours=1)
