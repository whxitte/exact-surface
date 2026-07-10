"""Per-stage timeout resolution + clamp to [MIN, MAX]."""

from __future__ import annotations

from taskqueue.timeouts import (
    DEFAULT_TIMEOUTS_SECONDS,
    MAX_TIMEOUT_SECONDS,
    MIN_TIMEOUT_SECONDS,
    effective_timeouts,
    sanitize_timeout_overrides,
)


def test_sanitize_clamps_and_drops_unknown():
    out = sanitize_timeout_overrides({"scan": 1, "ingest": 10_000_000, "bogus": 60, "probe": "x"})
    assert out["scan"] == MIN_TIMEOUT_SECONDS  # clamped up from 1s
    assert out["ingest"] == MAX_TIMEOUT_SECONDS  # clamped down
    assert "bogus" not in out and "probe" not in out  # unknown / non-int dropped


def test_effective_timeouts_precedence():
    eff = effective_timeouts(
        program_overrides={"scan": 1800},
        tenant_defaults={"scan": 3600, "crawl": 900},
    )
    assert eff["scan"] == 1800  # program wins over tenant
    assert eff["crawl"] == 900  # tenant wins over built-in
    assert eff["ingest"] == DEFAULT_TIMEOUTS_SECONDS["ingest"]  # untouched default


def test_effective_timeouts_empty_is_defaults():
    assert effective_timeouts() == DEFAULT_TIMEOUTS_SECONDS
