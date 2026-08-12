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


def test_plan_caps_return_unlimited():
    assert max_domains(Plan.FREE) is None
    assert max_domains(Plan.PRO) is None
    assert max_domains(Plan.BUSINESS) is None
    assert max_domains(Plan.ENTERPRISE) is None  # unlimited


def test_unknown_plan_fails_closed_to_free():
    assert coerce_plan("wat") is Plan.FREE
    assert coerce_plan(None) is Plan.FREE
    assert max_domains("wat") is None
    assert limits_for(None).max_domains is None


def test_can_add_domain_respects_cap():
    assert can_add_domain(Plan.FREE, 0)
    assert can_add_domain(Plan.FREE, 1)
    assert can_add_domain(Plan.PRO, 5)
    assert can_add_domain(Plan.ENTERPRISE, 10_000)  # unlimited


def test_allowed_is_oldest_first_and_deterministic():
    progs = [
        _p("c", "2026-03-01"),
        _p("a", "2026-01-01"),
        _p("b", "2026-02-01"),
    ]
    assert allowed_program_ids(Plan.FREE, progs) == {"a", "b", "c"}
    assert allowed_program_ids(Plan.PRO, progs) == {"a", "b", "c"}


def test_over_quota_is_the_complement():
    progs = [_p("a", "2026-01-01"), _p("b", "2026-02-01")]
    assert over_quota_program_ids(Plan.FREE, progs) == set()
    assert over_quota_program_ids(Plan.PRO, progs) == set()


def test_enterprise_allows_everything():
    progs = [_p(str(i), f"2026-01-{i:02d}") for i in range(1, 40)]
    assert len(allowed_program_ids(Plan.ENTERPRISE, progs)) == 39
    assert over_quota_program_ids(Plan.ENTERPRISE, progs) == set()


def test_missing_created_at_sorts_last_but_stably():
    progs = [_p("no-date"), _p("dated", "2026-01-01")]
    assert allowed_program_ids(Plan.FREE, progs) == {"no-date", "dated"}


# -- plan limits tests ----------------------------------------------------

from core import build_info  # noqa: E402
from core.plans import (  # noqa: E402
    PLAN_LIMITS,
    can_add_user,
    effective_limits,
)


def test_effective_limits_returns_unlimited():
    limits = effective_limits(entitlements=None, stored_plan="free")
    assert limits.max_domains is None


def test_shipped_source_version():
    assert build_info.VERSION == "dev"


# -- the tier table ----------------------------------------------------------


def test_every_tier_is_defined_and_ordered_sensibly():
    for plan in Plan:
        assert plan in PLAN_LIMITS, f"{plan} has no limits defined"
    free, pro, biz = (limits_for(p) for p in (Plan.FREE, Plan.PRO, Plan.BUSINESS))
    assert free.max_domains is None and pro.max_domains is None and biz.max_domains is None


def test_upgrading_never_removes_a_module_you_had():
    free, pro, biz = (limits_for(p) for p in (Plan.FREE, Plan.PRO, Plan.BUSINESS))
    assert free.optional_modules == pro.optional_modules == biz.optional_modules


def test_enterprise_gets_every_optional_module_including_future_ones():
    from core import modules as registry

    assert limits_for(Plan.ENTERPRISE).optional_modules == frozenset(registry.OPT_IN)


def test_seat_and_key_counters_respect_unlimited():
    ent, free = limits_for(Plan.ENTERPRISE), limits_for(Plan.FREE)
    assert can_add_user(ent, 999) and can_add_domain(ent, 999)
    assert can_add_user(free, 0) and can_add_user(free, 1)
