from __future__ import annotations

import pytest

from core.lifecycle import (
    FindingState,
    IllegalTransition,
    can_transition,
    on_reobserved,
    transition,
)


def test_happy_path_chain():
    s = FindingState.NEW
    for nxt in (FindingState.TRIAGED, FindingState.CONFIRMED, FindingState.RESOLVED):
        s = transition(s, nxt)
    assert s == FindingState.RESOLVED


def test_new_cannot_jump_to_confirmed():
    assert not can_transition(FindingState.NEW, FindingState.CONFIRMED)
    with pytest.raises(IllegalTransition):
        transition(FindingState.NEW, FindingState.CONFIRMED)


def test_resolved_reopens_as_regressed_and_alerts():
    state, alert = on_reobserved(FindingState.RESOLVED)
    assert state == FindingState.REGRESSED and alert is True


@pytest.mark.parametrize("s", [FindingState.FALSE_POSITIVE, FindingState.CONFIRMED])
def test_reobserving_open_or_suppressed_does_not_alert(s):
    state, alert = on_reobserved(s)
    assert state == s and alert is False


def test_regressed_can_be_triaged_again():
    assert can_transition(FindingState.REGRESSED, FindingState.TRIAGED)


def test_false_positive_can_regress():
    assert can_transition(FindingState.FALSE_POSITIVE, FindingState.REGRESSED)
