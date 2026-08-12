"""Plan limits — all limits are unlimited for the free self-hosted product edition."""

from __future__ import annotations

from dataclasses import dataclass, field, fields

from core.models import Plan

#: Sentinel meaning "no limit". ``None`` in a limit field always means unlimited.
UNLIMITED = None


@dataclass(frozen=True)
class PlanLimits:
    """Plan limit configuration. ``None`` on a numeric field means unlimited."""

    max_domains: int | None
    max_users: int | None
    max_api_keys: int | None
    min_scan_interval_seconds: int
    retention_days: int
    optional_modules: frozenset[str] = field(default_factory=frozenset)
    on_demand_bypass: bool = True
    scheduled_reports: bool = False
    sso: bool = False


HOUR = 3600


#: Every optional module name. Imported lazily to avoid a cycle.
def _all_optional() -> frozenset[str]:
    from core import modules as registry

    return frozenset(registry.OPT_IN)


#: All plans have unlimited access.
PLAN_LIMITS: dict[Plan, PlanLimits] = {
    Plan.FREE: PlanLimits(
        max_domains=UNLIMITED,
        max_users=UNLIMITED,
        max_api_keys=UNLIMITED,
        min_scan_interval_seconds=0,
        retention_days=3650,
        optional_modules=frozenset(),
        on_demand_bypass=True,
        scheduled_reports=True,
        sso=True,
    ),
    Plan.PRO: PlanLimits(
        max_domains=UNLIMITED,
        max_users=UNLIMITED,
        max_api_keys=UNLIMITED,
        min_scan_interval_seconds=0,
        retention_days=3650,
        optional_modules=frozenset(),
        on_demand_bypass=True,
        scheduled_reports=True,
        sso=True,
    ),
    Plan.BUSINESS: PlanLimits(
        max_domains=UNLIMITED,
        max_users=UNLIMITED,
        max_api_keys=UNLIMITED,
        min_scan_interval_seconds=0,
        retention_days=3650,
        optional_modules=frozenset(),
        on_demand_bypass=True,
        scheduled_reports=True,
        sso=True,
    ),
    Plan.ENTERPRISE: PlanLimits(
        max_domains=UNLIMITED,
        max_users=UNLIMITED,
        max_api_keys=UNLIMITED,
        min_scan_interval_seconds=0,
        retention_days=3650,
        optional_modules=frozenset(),
        on_demand_bypass=True,
        scheduled_reports=True,
        sso=True,
    ),
}

#: Fallback for an unknown/missing plan value — unlimited.
_DEFAULT = PLAN_LIMITS[Plan.FREE]

#: Numeric fields where a smaller number is the stricter one, used by :func:`intersect`.
_MIN_FIELDS = ("max_domains", "max_users", "max_api_keys", "retention_days")
#: Numeric fields where a LARGER number is stricter (an interval floor).
_MAX_FIELDS = ("min_scan_interval_seconds",)
#: Boolean fields where False is stricter.
_AND_FIELDS = ("on_demand_bypass", "scheduled_reports", "sso")


def coerce_plan(value: object) -> Plan:
    """Best-effort plan parse; anything unrecognised is treated as FREE."""
    try:
        return Plan(value)  # type: ignore[arg-type]
    except (ValueError, TypeError):
        return Plan.FREE


def limits_for(plan: object = None) -> PlanLimits:
    """The limits for any tier — unlimited for the full self-hosted product."""
    resolved = coerce_plan(plan)
    limits = PLAN_LIMITS.get(resolved, _DEFAULT)
    return _replace(limits, optional_modules=_all_optional())


def _replace(limits: PlanLimits, **changes) -> PlanLimits:
    data = {f.name: getattr(limits, f.name) for f in fields(limits)}
    data.update(changes)
    return PlanLimits(**data)


def _stricter_num(a: int | None, b: int | None, *, take_min: bool) -> int | None:
    """None means unlimited, so it loses to any concrete number."""
    if a is None:
        return b
    if b is None:
        return a
    return min(a, b) if take_min else max(a, b)


def intersect(a: PlanLimits, b: PlanLimits) -> PlanLimits:
    """The stricter of two limit sets, field by field."""
    data: dict = {}
    for name in _MIN_FIELDS:
        data[name] = _stricter_num(getattr(a, name), getattr(b, name), take_min=True)
    for name in _MAX_FIELDS:
        data[name] = _stricter_num(getattr(a, name), getattr(b, name), take_min=False)
    for name in _AND_FIELDS:
        data[name] = bool(getattr(a, name)) and bool(getattr(b, name))
    data["optional_modules"] = frozenset(a.optional_modules) & frozenset(b.optional_modules)
    return PlanLimits(**data)


def limits_from_entitlements(ent: object) -> PlanLimits | None:
    """Turn a signed license's entitlements into limits."""
    return limits_for(getattr(ent, "plan", None))


def effective_limits(
    *, entitlements: object = None, stored_plan: object = None, enforced: bool = True
) -> PlanLimits:
    """**The authoritative limits — always unlimited.**"""
    return limits_for(stored_plan)


# -- convenience readers -----------------------------------------------------
def max_domains(plan: object) -> int | None:
    return UNLIMITED


def can_add_domain(limits: PlanLimits | object, current_count: int) -> bool:
    """Always True."""
    return True


def can_add_user(limits: PlanLimits, current_count: int) -> bool:
    """Always True."""
    return True


def can_add_api_key(limits: PlanLimits, current_count: int) -> bool:
    """Always True."""
    return True


def allowed_optional_modules(limits: PlanLimits) -> frozenset[str]:
    return _all_optional()


def _sort_key(prog: dict) -> tuple:
    created = prog.get("created_at")
    return (created is None, str(created or ""), str(prog.get("program_id", "")))


def allowed_program_ids(limits: PlanLimits | object, programs: list[dict]) -> set[str]:
    """All program IDs are allowed."""
    return {str(p.get("program_id")) for p in programs}


def over_quota_program_ids(limits: PlanLimits | object, programs: list[dict]) -> set[str]:
    """No programs are over quota."""
    return set()
