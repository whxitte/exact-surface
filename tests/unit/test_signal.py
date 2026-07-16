"""Signal-quality summary + §15 false-positive rate (core/signal.py)."""

from __future__ import annotations

from core.lifecycle import FindingState
from core.signal import is_actionable, summarize_findings


def _f(severity="info", state=FindingState.NEW.value, is_new=True):
    return {"severity": severity, "state": state, "is_new": is_new}


def test_actionable_requires_open_and_medium_plus():
    assert is_actionable(_f("high"))
    assert is_actionable(_f("medium"))
    assert not is_actionable(_f("low"))  # below floor
    assert not is_actionable(_f("info"))  # below floor
    # a high finding that's been resolved/suppressed is no longer actionable
    assert not is_actionable(_f("high", state=FindingState.RESOLVED.value))
    assert not is_actionable(_f("critical", state=FindingState.FALSE_POSITIVE.value))
    # regressed high is open again → actionable
    assert is_actionable(_f("high", state=FindingState.REGRESSED.value))


def test_actionable_vs_informational_split():
    findings = [
        _f("critical"),
        _f("high"),
        _f("medium"),
        _f("low"),  # informational
        _f("info"),  # informational
        _f("info"),  # informational
    ]
    s = summarize_findings(findings)
    assert s["total"] == 6
    assert s["open_actionable"] == 3  # critical, high, medium
    assert s["informational"] == 3  # low, info, info
    assert s["by_severity"] == {"critical": 1, "high": 1, "medium": 1, "low": 1, "info": 2}


def test_false_positive_rate_over_decided_only():
    findings = [
        _f("high", state=FindingState.FALSE_POSITIVE.value),
        _f("high", state=FindingState.FALSE_POSITIVE.value),
        _f("high", state=FindingState.CONFIRMED.value),
        _f("high", state=FindingState.RESOLVED.value),
        _f("high", state=FindingState.ACCEPTED_RISK.value),
        # undecided — must NOT count toward the denominator
        _f("high", state=FindingState.NEW.value),
        _f("high", state=FindingState.TRIAGED.value),
    ]
    s = summarize_findings(findings)
    assert s["decided"] == 5  # 2 FP + confirmed + resolved + accepted
    assert s["false_positives"] == 2
    assert s["false_positive_rate"] == 0.4  # 2/5


def test_fp_rate_is_none_until_something_is_decided():
    """An account with only NEW findings has an *undefined* FP rate, not 0% —
    so a brand-new tenant doesn't look artificially perfect."""
    s = summarize_findings([_f("high"), _f("critical")])
    assert s["false_positive_rate"] is None
    assert s["decided"] == 0


def test_empty_is_safe():
    s = summarize_findings([])
    assert s == {
        "total": 0,
        "new": 0,
        "open_actionable": 0,
        "informational": 0,
        "by_severity": {},
        "by_state": {},
        "decided": 0,
        "false_positives": 0,
        "false_positive_rate": None,
    }


def test_unknown_severity_is_treated_as_info_noise():
    s = summarize_findings([_f("bogus")])
    assert s["open_actionable"] == 0 and s["informational"] == 1
