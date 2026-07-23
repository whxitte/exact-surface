"""Finding lifecycle state machine (§5c).

Richer than a bare ``is_new`` boolean: a finding moves through explicit states so
triage, suppression, and regression detection are unambiguous and auditable.

    NEW ──▶ TRIAGED ──▶ CONFIRMED ──▶ RESOLVED
              │              │             │
              ├──▶ FALSE_POSITIVE          └──(reappears)──▶ REGRESSED (=NEW, alerts once)
              └──▶ ACCEPTED_RISK

Transitions are validated by :func:`can_transition`; illegal moves raise so a bug
can never silently corrupt a finding's history.
"""

from __future__ import annotations

from enum import Enum

from core.errors import ExactSurfaceError


class FindingState(str, Enum):
    NEW = "new"
    TRIAGED = "triaged"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"
    RESOLVED = "resolved"
    REGRESSED = "regressed"


#: Allowed transitions. REGRESSED behaves like NEW (re-enters triage, alerts once).
_ALLOWED: dict[FindingState, frozenset[FindingState]] = {
    FindingState.NEW: frozenset(
        {FindingState.TRIAGED, FindingState.FALSE_POSITIVE, FindingState.RESOLVED}
    ),
    FindingState.TRIAGED: frozenset(
        {
            FindingState.CONFIRMED,
            FindingState.FALSE_POSITIVE,
            FindingState.ACCEPTED_RISK,
            FindingState.RESOLVED,
        }
    ),
    FindingState.CONFIRMED: frozenset({FindingState.RESOLVED, FindingState.ACCEPTED_RISK}),
    FindingState.FALSE_POSITIVE: frozenset({FindingState.REGRESSED, FindingState.TRIAGED}),
    FindingState.ACCEPTED_RISK: frozenset({FindingState.TRIAGED, FindingState.RESOLVED}),
    FindingState.RESOLVED: frozenset({FindingState.REGRESSED}),
    FindingState.REGRESSED: frozenset(
        {FindingState.TRIAGED, FindingState.CONFIRMED, FindingState.RESOLVED}
    ),
}

#: States in which a re-observation should NOT re-alert (already handled/known).
SUPPRESSED_STATES: frozenset[FindingState] = frozenset(
    {FindingState.FALSE_POSITIVE, FindingState.ACCEPTED_RISK}
)

#: States that count as "open" for dashboards.
OPEN_STATES: frozenset[FindingState] = frozenset(
    {FindingState.NEW, FindingState.TRIAGED, FindingState.CONFIRMED, FindingState.REGRESSED}
)


class IllegalTransition(ExactSurfaceError):
    def __init__(self, src: FindingState, dst: FindingState) -> None:
        super().__init__(f"illegal finding transition: {src.value} -> {dst.value}")


def can_transition(src: FindingState, dst: FindingState) -> bool:
    return dst in _ALLOWED.get(src, frozenset())


def transition(src: FindingState, dst: FindingState) -> FindingState:
    """Return *dst* if the move is legal, else raise :class:`IllegalTransition`."""
    if not can_transition(src, dst):
        raise IllegalTransition(src, dst)
    return dst


def on_reobserved(current: FindingState) -> tuple[FindingState, bool]:
    """Decide what happens when a still-present finding is seen again.

    Returns ``(next_state, should_alert)``. A ``RESOLVED`` finding that reappears
    regresses and alerts once; suppressed states stay put and do not alert;
    everything else is unchanged and does not re-alert.
    """
    if current == FindingState.RESOLVED:
        return FindingState.REGRESSED, True
    return current, False
