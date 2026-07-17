"""Plan limits (§13) — core/plans.py."""

from __future__ import annotations

from core.models import Plan
from core.plans import (
    allowed_program_ids,
    can_add_domain,
    coerce_plan,
    limits_for,
    max_domains,
    over_quota_program_ids,
)


def _p(pid: str, created: str | None = None) -> dict:
    return {"program_id": pid, "created_at": created}


def test_tier_caps_match_the_commercial_model():
    assert max_domains(Plan.FREE) == 1
    assert max_domains(Plan.PRO) == 5
    assert max_domains(Plan.BUSINESS) == 25
    assert max_domains(Plan.ENTERPRISE) is None  # unlimited


def test_unknown_plan_fails_closed_to_free():
    # A corrupt/missing plan value must never grant unlimited scanning.
    assert coerce_plan("wat") is Plan.FREE
    assert coerce_plan(None) is Plan.FREE
    assert max_domains("wat") == 1
    assert limits_for(None).max_domains == 1


def test_can_add_domain_respects_cap():
    assert can_add_domain(Plan.FREE, 0)
    assert not can_add_domain(Plan.FREE, 1)
    assert can_add_domain(Plan.PRO, 4)
    assert not can_add_domain(Plan.PRO, 5)
    assert can_add_domain(Plan.ENTERPRISE, 10_000)  # unlimited


def test_allowed_is_oldest_first_and_deterministic():
    progs = [
        _p("c", "2026-03-01"),
        _p("a", "2026-01-01"),
        _p("b", "2026-02-01"),
    ]
    # Free keeps only the oldest; repeated calls agree (no shifting subset).
    assert allowed_program_ids(Plan.FREE, progs) == {"a"}
    assert allowed_program_ids(Plan.FREE, list(reversed(progs))) == {"a"}
    assert allowed_program_ids(Plan.PRO, progs) == {"a", "b", "c"}


def test_over_quota_is_the_complement():
    progs = [_p("a", "2026-01-01"), _p("b", "2026-02-01")]
    assert over_quota_program_ids(Plan.FREE, progs) == {"b"}
    assert over_quota_program_ids(Plan.PRO, progs) == set()


def test_enterprise_allows_everything():
    progs = [_p(str(i), f"2026-01-{i:02d}") for i in range(1, 40)]
    assert len(allowed_program_ids(Plan.ENTERPRISE, progs)) == 39
    assert over_quota_program_ids(Plan.ENTERPRISE, progs) == set()


def test_missing_created_at_sorts_last_but_stably():
    progs = [_p("no-date"), _p("dated", "2026-01-01")]
    # The dated program wins the single Free slot; the undated one is over quota.
    assert allowed_program_ids(Plan.FREE, progs) == {"dated"}
    assert allowed_program_ids(Plan.FREE, list(reversed(progs))) == {"dated"}
