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


# -- authority: the licence, not the database --------------------------------
# These are bypass tests. Plan enforcement in a self-hosted product is a prime target:
# the customer owns the machine, the database and the environment, so every check must
# anchor to something they cannot edit. That anchor is the Ed25519-signed licence.

from datetime import UTC, datetime, timedelta  # noqa: E402

from core import build_info  # noqa: E402
from core.license import Entitlements  # noqa: E402
from core.plans import (  # noqa: E402
    PLAN_LIMITS,
    can_add_user,
    effective_limits,
    intersect,
)


def _ent(**over) -> Entitlements:
    base = dict(
        license_id="lic_1",
        customer_id="cus_1",
        customer_name="Acme",
        plan=Plan.BUSINESS,
        max_domains=25,
        max_users=15,
        features=frozenset(),
        issued_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(days=30),
        grace_days=7,
    )
    base.update(over)
    return Entitlements(**base)


def test_stored_plan_cannot_raise_a_limit_above_the_licence():
    """THE test. A self-hosted customer owns their database, so they can set
    `plan: "enterprise"` on their tenant whenever they like. It must buy them nothing."""
    forged = effective_limits(entitlements=_ent(max_domains=1), stored_plan="enterprise")
    assert forged.max_domains == 1, (
        "editing the tenant document in Mongo raised the domain limit above the signed "
        "licence — the entire commercial model would be bypassable"
    )


def test_stored_plan_is_ignored_entirely_when_a_licence_is_present():
    """Not intersected — ignored. Leaving a customer-controlled value anywhere in the
    decision is all a bypass needs, in either direction."""
    for claimed in ("free", "enterprise", "nonsense", None):
        limits = effective_limits(entitlements=_ent(max_domains=25), stored_plan=claimed)
        assert limits.max_domains == 25, claimed


def test_intersection_takes_the_stricter_side_on_every_axis():
    a, b = limits_for(Plan.BUSINESS), limits_for(Plan.FREE)
    both = intersect(a, b)
    assert both.max_domains == 1
    # A LARGER interval is the stricter one — a floor, not a cap.
    assert both.min_scan_interval_seconds == max(
        a.min_scan_interval_seconds, b.min_scan_interval_seconds
    )
    assert both.on_demand_bypass is False
    assert both.optional_modules == a.optional_modules & b.optional_modules


def test_unlimited_never_beats_a_concrete_limit():
    unlimited = limits_for(Plan.ENTERPRISE)
    assert intersect(unlimited, limits_for(Plan.FREE)).max_domains == 1
    assert intersect(limits_for(Plan.FREE), unlimited).max_domains == 1


def test_no_licence_falls_back_to_the_stored_plan_never_to_unlimited():
    assert effective_limits(entitlements=None, stored_plan="free").max_domains == 1
    assert effective_limits(entitlements=None, stored_plan=None).max_domains == 1
    assert effective_limits(entitlements=None, stored_plan="nonsense").max_domains == 1


def test_licence_can_grant_more_domains_than_its_tier():
    """The deal you will actually close is "Business, but they need 30 domains". The
    licence states the number, so this needs no new tier."""
    limits = effective_limits(
        entitlements=_ent(plan=Plan.BUSINESS, max_domains=30), stored_plan="business"
    )
    assert limits.max_domains == 30


def test_licence_can_unlock_one_optional_module_without_a_tier_change():
    ent = _ent(plan=Plan.PRO, features=frozenset({"cloud_buckets"}))
    limits = effective_limits(entitlements=ent, stored_plan="pro")
    assert "cloud_buckets" in limits.optional_modules
    assert "param_discovery" in limits.optional_modules  # the tier's own set survives


# -- enforcement is not an environment variable ------------------------------


def test_release_build_enforces_licensing_regardless_of_the_setting(monkeypatch):
    """`docker run -e EXACTSURFACE_LICENSE_ENFORCED=false` must not switch off the
    subscription. A release image is enforced because of what it is."""
    monkeypatch.setattr(build_info, "RELEASE_BUILD", True)
    assert build_info.licence_enforced(settings_flag=False) is True


def test_source_checkout_honours_the_setting(monkeypatch):
    monkeypatch.setattr(build_info, "RELEASE_BUILD", False)
    assert build_info.licence_enforced(settings_flag=False) is False
    assert build_info.licence_enforced(settings_flag=True) is True


def test_shipped_source_is_not_marked_as_a_release_build():
    """Only scripts/stamp_build.py flips this, in the pipeline. A True here would make
    every developer's checkout demand a licence."""
    assert build_info.RELEASE_BUILD is False
    assert build_info.VERSION == "dev"


# -- the tier table ----------------------------------------------------------


def test_every_tier_is_defined_and_ordered_sensibly():
    for plan in Plan:
        assert plan in PLAN_LIMITS, f"{plan} has no limits defined"
    free, pro, biz = (limits_for(p) for p in (Plan.FREE, Plan.PRO, Plan.BUSINESS))
    assert free.max_domains < pro.max_domains < biz.max_domains
    assert free.max_users < pro.max_users < biz.max_users
    assert free.min_scan_interval_seconds >= pro.min_scan_interval_seconds
    assert pro.min_scan_interval_seconds >= biz.min_scan_interval_seconds
    assert free.retention_days < pro.retention_days < biz.retention_days


def test_upgrading_never_removes_a_module_you_had():
    free, pro, biz = (limits_for(p) for p in (Plan.FREE, Plan.PRO, Plan.BUSINESS))
    assert free.optional_modules <= pro.optional_modules <= biz.optional_modules


def test_enterprise_gets_every_optional_module_including_future_ones():
    """Enterprise means "all of them", resolved from the module registry — so a module
    added tomorrow is sold to Enterprise without editing the plan table."""
    from core import modules as registry

    assert limits_for(Plan.ENTERPRISE).optional_modules == frozenset(registry.OPT_IN)


def test_unimplemented_features_are_off_on_every_tier():
    """SSO is reserved but not built. It must not be advertised as available until it
    is — a limit that reads as granted but does nothing is the same lie in reverse."""
    assert not any(limits_for(p).sso for p in Plan)


def test_seat_and_key_counters_respect_unlimited():
    ent, free = limits_for(Plan.ENTERPRISE), limits_for(Plan.FREE)
    assert can_add_user(ent, 999) and can_add_domain(ent, 999)
    assert can_add_user(free, 0) and not can_add_user(free, 1)
