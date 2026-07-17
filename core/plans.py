"""Plan limits (§13) — what each tier is allowed to do.

Only ``max_domains`` is enforced today; the other §13 tier differences (retention
windows, priority queue, SSO, channel availability) are deliberately NOT modelled
here yet, because a limit that exists in a table but is never checked is worse
than no limit at all — it reads as enforced when it isn't.

Enforcement happens in two places, per §13 ("plan limits are checked at
enqueue"):

* **program creation** — an over-quota tenant cannot add another domain;
* **enqueue / scan start** — the authoritative gate, so a *downgrade* takes
  effect immediately: a tenant who drops from Business (25) to Free (1) keeps
  their program records, but only the allowance is scanned. Nothing is deleted.

Which programs stay inside the allowance on a downgrade is deterministic —
oldest first by ``created_at`` (ties broken by ``program_id``) — so the same
programs are chosen on every tick and the customer sees stable behaviour rather
than a random subset each run.
"""

from __future__ import annotations

from dataclasses import dataclass

from core.models import Plan


@dataclass(frozen=True)
class PlanLimits:
    #: Maximum programs (domains) that may be scanned. ``None`` = unlimited.
    max_domains: int | None


#: §13 commercial model. Enterprise is unlimited.
PLAN_LIMITS: dict[Plan, PlanLimits] = {
    Plan.FREE: PlanLimits(max_domains=1),
    Plan.PRO: PlanLimits(max_domains=5),
    Plan.BUSINESS: PlanLimits(max_domains=25),
    Plan.ENTERPRISE: PlanLimits(max_domains=None),
}

#: Fallback for an unknown/missing plan value — never fail open to unlimited.
_DEFAULT = PLAN_LIMITS[Plan.FREE]


def coerce_plan(value: object) -> Plan:
    """Best-effort plan parse; anything unrecognised is treated as FREE."""
    try:
        return Plan(value)  # type: ignore[arg-type]
    except (ValueError, TypeError):
        return Plan.FREE


def limits_for(plan: object) -> PlanLimits:
    return PLAN_LIMITS.get(coerce_plan(plan), _DEFAULT)


def max_domains(plan: object) -> int | None:
    return limits_for(plan).max_domains


def can_add_domain(plan: object, current_count: int) -> bool:
    cap = max_domains(plan)
    return True if cap is None else current_count < cap


def _sort_key(prog: dict) -> tuple:
    # created_at may be absent on legacy docs — sort those last but stably.
    created = prog.get("created_at")
    return (created is None, str(created or ""), str(prog.get("program_id", "")))


def allowed_program_ids(plan: object, programs: list[dict]) -> set[str]:
    """The subset of *programs* inside the plan's allowance (oldest first).

    Deterministic so a downgraded tenant sees the same programs scanned on every
    tick instead of a shifting subset.
    """
    cap = max_domains(plan)
    if cap is None:
        return {str(p.get("program_id")) for p in programs}
    ordered = sorted(programs, key=_sort_key)
    return {str(p.get("program_id")) for p in ordered[:cap]}


def over_quota_program_ids(plan: object, programs: list[dict]) -> set[str]:
    """Programs that exist but fall outside the plan's allowance."""
    allowed = allowed_program_ids(plan, programs)
    return {str(p.get("program_id")) for p in programs} - allowed
