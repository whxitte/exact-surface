"""Plan limits — what each tier may do, and where the authority for that comes from.

The critical rule in a self-hosted product
------------------------------------------
**The signed license is the authority. The database is not.**

ExactSurface runs on the customer's own infrastructure, which means they own the
database. A tenant document saying ``plan: "enterprise"`` is a *claim by the customer
about themselves*, and trusting it would make every limit in this file decorative — one
``db.tenants.updateOne({}, {$set: {plan: "enterprise"}})`` and the product is unlimited.

So the resolution is simple and absolute:

* **if there is a valid licence, it is the only input.** The stored plan is ignored
  entirely. Not intersected, not consulted — ignored. Anything else leaves a value the
  customer controls somewhere in the decision, and "somewhere in the decision" is all a
  bypass needs;
* **if there is no licence** (a source checkout with enforcement off — never a release
  image, see ``core.build_info``) the stored plan is all there is, so it is used. This
  path lets developers and tests exercise tier behaviour without minting licences.

An earlier version intersected the two, so that an admin could voluntarily restrict a
staging deployment below what they had paid for. That was dropped: it made a
per-customer grant ("Business, but 30 domains") get silently clamped back to the tier
default, which is the opposite of what the licence is for. Voluntary self-restriction
is a feature nobody asked for; a correct commercial model is not.

Every limit here is enforced somewhere. A limit that exists in a table but is never
checked is worse than no limit: it reads as enforced when it isn't. The
``enforced_at`` field on each limit names the module that checks it, and
``tests/unit/test_plans.py`` asserts none of them is orphaned.
"""

from __future__ import annotations

from dataclasses import dataclass, field, fields

from core.models import Plan

#: Sentinel meaning "no limit". ``None`` in a limit field always means unlimited.
UNLIMITED = None


@dataclass(frozen=True)
class PlanLimits:
    """What a tier allows. ``None`` on a numeric field means unlimited."""

    #: Programs (domains) that get scanned. Enforced: api.routes.programs (create),
    #: taskqueue.scheduler (enqueue — so a downgrade takes effect without deleting).
    max_domains: int | None
    #: Members in the tenant. Enforced: api.routes.members (invite/create).
    max_users: int | None
    #: API keys for integrations. Enforced: api.routes.apikeys.
    max_api_keys: int | None
    #: Politeness/cost floor on re-scan frequency. A plan cannot scan faster than this,
    #: whatever cadence the user sets. Enforced: taskqueue.cadence.sanitize_overrides.
    min_scan_interval_seconds: int
    #: How long findings and scan history are kept. Enforced: scripts.retention.
    retention_days: int
    #: Optional modules this tier may switch on. Empty = the always-on set only.
    #: Enforced: core.modules.resolve via allowed_optional_modules.
    optional_modules: frozenset[str] = field(default_factory=frozenset)
    #: On-demand 403/401 bypass. Enforced: api.routes.programs (bypass-403).
    on_demand_bypass: bool = True
    #: Scheduled PDF/HTML reporting. Enforced: api.routes.reports.
    scheduled_reports: bool = False
    #: SSO / SAML. Enforced: api.routes.auth (reserved — not implemented yet, so it is
    #: False everywhere rather than advertised as available on a tier.)
    sso: bool = False


HOUR = 3600

#: Every optional module name, so a tier can be given "all of them" without this file
#: needing an edit each time one is added. Imported lazily to avoid a cycle.
def _all_optional() -> frozenset[str]:
    from core import modules as registry

    return frozenset(registry.OPT_IN)


#: The commercial model. Tiers differ on the axes a customer actually feels: how many
#: domains, how many people, how often, how long the history, and how deep the scan.
PLAN_LIMITS: dict[Plan, PlanLimits] = {
    Plan.FREE: PlanLimits(
        max_domains=1,
        max_users=1,
        max_api_keys=1,
        min_scan_interval_seconds=24 * HOUR,
        retention_days=30,
        optional_modules=frozenset(),
        on_demand_bypass=False,
        scheduled_reports=False,
    ),
    Plan.PRO: PlanLimits(
        max_domains=5,
        max_users=3,
        max_api_keys=3,
        min_scan_interval_seconds=6 * HOUR,
        retention_days=180,
        optional_modules=frozenset({"tls", "service_scan", "param_discovery"}),
        on_demand_bypass=True,
        scheduled_reports=True,
    ),
    Plan.BUSINESS: PlanLimits(
        max_domains=25,
        max_users=15,
        max_api_keys=10,
        min_scan_interval_seconds=1 * HOUR,
        retention_days=365,
        optional_modules=frozenset({
            "tls", "service_scan", "param_discovery", "typosquat",
            "cloud_buckets", "nuclei_watch", "dork", "uncover",
        }),
        on_demand_bypass=True,
        scheduled_reports=True,
    ),
    Plan.ENTERPRISE: PlanLimits(
        max_domains=UNLIMITED,
        max_users=UNLIMITED,
        max_api_keys=UNLIMITED,
        min_scan_interval_seconds=15 * 60,
        retention_days=1095,
        optional_modules=frozenset(),  # replaced by _all_optional() in limits_for
        on_demand_bypass=True,
        scheduled_reports=True,
    ),
}

#: Fallback for an unknown/missing plan value — never fail open to unlimited.
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


def limits_for(plan: object) -> PlanLimits:
    """The published limits for a tier. Not the authority — see :func:`effective_limits`."""
    resolved = coerce_plan(plan)
    limits = PLAN_LIMITS.get(resolved, _DEFAULT)
    if resolved is Plan.ENTERPRISE:
        # Enterprise gets every optional module, including ones added after this file
        # was last edited — otherwise a new module silently isn't sold to anybody.
        return _replace(limits, optional_modules=_all_optional())
    return limits


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
    """The stricter of two limit sets, field by field.

    Used to combine the license ceiling with the stored plan. Whichever is tighter
    wins on every axis independently, so a mismatched pair can never widen anything.
    """
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
    """Turn a signed license's entitlements into limits.

    The license carries the tier plus explicit per-customer overrides for the two things
    that are actually sold by quantity — domains and users — because "Business plus five
    extra domains" is a real deal you will close, and re-cutting the tier table for it
    would be absurd. Anything the license does not state falls back to its tier.
    """
    if ent is None:
        return None
    base = limits_for(getattr(ent, "plan", None))
    overrides: dict = {}
    for name in ("max_domains", "max_users"):
        value = getattr(ent, name, "__missing__")
        if value != "__missing__":
            overrides[name] = value
    # `features` is the per-customer optional-module grant. An empty set means "use the
    # tier's default"; a non-empty one is added to it, so a licence can unlock a single
    # module without moving the customer up a whole tier.
    features = frozenset(getattr(ent, "features", ()) or ())
    if features:
        overrides["optional_modules"] = frozenset(base.optional_modules) | features
    return _replace(base, **overrides)


def effective_limits(
    *, entitlements: object = None, stored_plan: object = None, enforced: bool = True
) -> PlanLimits:
    """**The authoritative limits.**

    A valid licence is the *sole* input — the stored plan is not consulted at all,
    because it lives in a database the customer owns. With no licence (dev only; a
    release image always enforces) the stored plan is used, so tier behaviour stays
    testable without minting tokens.

    ``enforced`` is accepted for call-site clarity but does not change the result: an
    unlicensed instance with enforcement on is already read-only via the licence state,
    so there is no quota left to protect.
    """
    licensed = limits_from_entitlements(entitlements)
    return licensed if licensed is not None else limits_for(stored_plan)


# -- convenience readers -----------------------------------------------------
def max_domains(plan: object) -> int | None:
    return limits_for(plan).max_domains


def can_add_domain(limits: PlanLimits | object, current_count: int) -> bool:
    """True if another domain fits. Accepts limits or a bare plan value."""
    resolved = limits if isinstance(limits, PlanLimits) else limits_for(limits)
    cap = resolved.max_domains
    return True if cap is None else current_count < cap


def can_add_user(limits: PlanLimits, current_count: int) -> bool:
    cap = limits.max_users
    return True if cap is None else current_count < cap


def can_add_api_key(limits: PlanLimits, current_count: int) -> bool:
    cap = limits.max_api_keys
    return True if cap is None else current_count < cap


def allowed_optional_modules(limits: PlanLimits) -> frozenset[str]:
    return frozenset(limits.optional_modules)


def _sort_key(prog: dict) -> tuple:
    # created_at may be absent on legacy docs — sort those last but stably.
    created = prog.get("created_at")
    return (created is None, str(created or ""), str(prog.get("program_id", "")))


def allowed_program_ids(limits: PlanLimits | object, programs: list[dict]) -> set[str]:
    """The subset of *programs* inside the allowance (oldest first).

    Deterministic so a downgraded tenant sees the same programs scanned on every tick
    instead of a shifting subset. Nothing is ever deleted — the excess simply stops
    being scanned, and starts again if they upgrade.
    """
    resolved = limits if isinstance(limits, PlanLimits) else limits_for(limits)
    cap = resolved.max_domains
    if cap is None:
        return {str(p.get("program_id")) for p in programs}
    ordered = sorted(programs, key=_sort_key)
    return {str(p.get("program_id")) for p in ordered[:cap]}


def over_quota_program_ids(limits: PlanLimits | object, programs: list[dict]) -> set[str]:
    """Programs that exist but fall outside the allowance."""
    allowed = allowed_program_ids(limits, programs)
    return {str(p.get("program_id")) for p in programs} - allowed
