"""Signal-quality summary — separate actionable findings from inventory noise
and compute the §15 make-or-break metric: the user-marked false-positive rate.

A real scan can emit hundreds of *informational* detections (tech fingerprints,
TLS version, CAA records, missing security headers). Those are inventory, not
work. The dashboard should surface the handful that are **actionable** — open
(not yet resolved/suppressed) *and* at or above the actionable severity floor —
and report how noisy the product has been (false-positive rate), because a low
FP rate is what makes an EASM credible (§15, target < 5%).

Pure functions over plain finding dicts (as stored), so they are trivially unit
tested and reused by both the ``/stats`` route and any metrics exporter.
"""

from __future__ import annotations

from core.lifecycle import OPEN_STATES, FindingState
from core.severity import Severity

#: A finding is "actionable" at or above this severity; below it is informational.
ACTIONABLE_FLOOR: Severity = Severity.MEDIUM

#: Terminal states that represent an explicit human judgement (the FP-rate
#: denominator). TRIAGED is in-progress and REGRESSED is re-opened — neither is a
#: final call, so both are excluded.
DECIDED_STATES: frozenset[FindingState] = frozenset(
    {
        FindingState.FALSE_POSITIVE,
        FindingState.CONFIRMED,
        FindingState.ACCEPTED_RISK,
        FindingState.RESOLVED,
    }
)

_OPEN_VALUES = {s.value for s in OPEN_STATES}
_DECIDED_VALUES = {s.value for s in DECIDED_STATES}


def _severity_rank(value: str) -> int:
    try:
        return Severity(value).rank
    except ValueError:
        return Severity.INFO.rank


def is_actionable(doc: dict) -> bool:
    """Open (still needs attention) and at/above the actionable severity floor."""
    state = doc.get("state", FindingState.NEW.value)
    if state not in _OPEN_VALUES:
        return False
    return _severity_rank(doc.get("severity", "info")) >= ACTIONABLE_FLOOR.rank


def summarize_findings(findings: list[dict]) -> dict:
    """Signal-quality rollup for a set of finding docs.

    Returns counts split into actionable vs informational, a per-state and
    per-severity breakdown, and the false-positive rate (``None`` until the user
    has decided at least one finding, so an empty account doesn't read as 0%).
    """
    by_severity: dict[str, int] = {}
    by_state: dict[str, int] = {}
    actionable = informational = new = decided = false_positives = 0

    for f in findings:
        sev = f.get("severity", "info")
        state = f.get("state", FindingState.NEW.value)
        by_severity[sev] = by_severity.get(sev, 0) + 1
        by_state[state] = by_state.get(state, 0) + 1
        if f.get("is_new"):
            new += 1
        if is_actionable(f):
            actionable += 1
        elif _severity_rank(sev) < ACTIONABLE_FLOOR.rank:
            informational += 1
        if state in _DECIDED_VALUES:
            decided += 1
            if state == FindingState.FALSE_POSITIVE.value:
                false_positives += 1

    fp_rate = round(false_positives / decided, 4) if decided else None
    return {
        "total": len(findings),
        "new": new,
        "open_actionable": actionable,
        "informational": informational,
        "by_severity": by_severity,
        "by_state": by_state,
        "decided": decided,
        "false_positives": false_positives,
        "false_positive_rate": fp_rate,
    }
