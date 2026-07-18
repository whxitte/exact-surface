"""Asset interest triage (§4 core.fingerprint.classify_interest).

Replaces an earlier numeric interest_score that nothing consumed. The value is a
triage level PLUS the reasons for it, from the signals httpx already returns — so a
researcher sees the handful of hosts worth a look and *why*. Aligned with the
auth-bypass / 401-403 focus: an exposed Jenkins, an admin panel, an auth boundary.
"""

from __future__ import annotations

from core.fingerprint import INTEREST_LEVELS, classify_interest


def test_exposed_devops_tech_is_critical_with_a_reason():
    level, reasons = classify_interest("ci.example.com", tech=["Jenkins"])
    assert level == "critical"
    assert any("Jenkins" in r for r in reasons)


def test_admin_in_the_page_title_is_critical():
    """A signal the old host-only score ignored entirely."""
    level, reasons = classify_interest("app.example.com", title="Admin Dashboard")
    assert level == "critical"
    assert reasons


def test_401_is_flagged_as_an_auth_bypass_target():
    level, reasons = classify_interest("api.example.com", status=401)
    # api host is 'high' on its own; 401 keeps it high and adds the reason
    assert level == "high"
    assert any("401" in r for r in reasons)


def test_reverse_proxy_hidden_product_still_caught_by_hostname():
    """httpx sees nginx, but kibana.* in the hostname gives it away."""
    level, reasons = classify_interest("kibana.internal.example.com", tech=["nginx"])
    assert level == "critical"


def test_ephemeral_host_raises_interest():
    level, reasons = classify_interest("staging.example.com")
    assert level == "high"
    assert any("forgotten env" in r for r in reasons)


def test_highest_level_wins_but_all_reasons_kept():
    level, reasons = classify_interest(
        "admin.example.com", tech=["WordPress"], title="Login", status=403
    )
    assert level == "critical"  # admin host beats wordpress/login/403
    assert len(reasons) >= 3  # every match contributes a reason


def test_a_plain_marketing_host_is_low():
    level, reasons = classify_interest("www.example.com", tech=["React"], status=200)
    assert level == "low"


def test_static_asset_host_is_low_noise():
    level, _ = classify_interest("static.example.com", status=200)
    assert level == "low"


def test_level_is_always_a_known_value():
    for host in ("x.example.com", "admin.x.com", "cdn.x.com", "grafana.x.com"):
        level, _ = classify_interest(host)
        assert level in INTEREST_LEVELS


def test_reasons_are_deduped():
    # 'jira' matches both a host rule and a tech rule; the reason list must not repeat
    level, reasons = classify_interest("jira.example.com", tech=["Jira"])
    assert level == "critical"
    assert len(reasons) == len(set(reasons))
