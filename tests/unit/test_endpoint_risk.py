"""Endpoint risk classification (§7 signal quality).

Crawling surfaces hundreds of URLs; this tags the handful worth a human's attention
— auth flows, admin, APIs, and the IDOR/SSRF/redirect parameter surface the user
called out. It is classification only (a label, never a scan), so the bar is "does
the right URL get the right tag", and noise (static assets) gets none.
"""

from __future__ import annotations

from core.endpoint_risk import classify_endpoint, is_noise


def test_static_assets_and_trackers_are_noise():
    assert is_noise("https://x.com/assets/app.9f2.css")
    assert is_noise("https://x.com/logo.png?v=2")
    assert is_noise("https://www.google-analytics.com/collect")
    assert classify_endpoint("https://x.com/img/logo.svg") == []


def test_auth_surfaces_are_tagged():
    assert "auth" in classify_endpoint("https://x.com/login")
    assert "auth" in classify_endpoint("https://x.com/account/reset-password")
    assert "auth" in classify_endpoint("https://x.com/oauth/authorize?client_id=1")
    assert "token" in classify_endpoint("https://x.com/api/refresh_token")


def test_admin_and_debug_surfaces():
    assert "admin" in classify_endpoint("https://x.com/admin/users")
    assert "admin" in classify_endpoint("https://x.com/internal/dashboard")
    assert "debug" in classify_endpoint("https://x.com/actuator/health")


def test_api_surfaces():
    assert "api" in classify_endpoint("https://x.com/api/v2/users")
    assert "api" in classify_endpoint("https://x.com/v1/orders")
    assert "graphql" in classify_endpoint("https://x.com/graphql")
    assert "api-docs" in classify_endpoint("https://x.com/swagger-ui.html")


def test_the_injectable_parameter_surface():
    """The IDOR / SSRF / LFI surface the user flagged — classified from the query."""
    assert "idor" in classify_endpoint("https://x.com/account?user_id=42")
    assert "ssrf" in classify_endpoint("https://x.com/fetch?url=http://169.254.169.254/")
    assert "ssrf" in classify_endpoint("https://x.com/go?redirect=//evil.com")
    assert "lfi" in classify_endpoint("https://x.com/view?file=../../etc/passwd")


def test_exposure_and_payment():
    assert "exposure" in classify_endpoint("https://x.com/.env")
    assert "exposure" in classify_endpoint("https://x.com/backup/db.sql")
    assert "exposure" in classify_endpoint("https://x.com/site.zip")
    assert "payment" in classify_endpoint("https://x.com/checkout/confirm")


def test_a_url_can_collect_several_tags():
    tags = classify_endpoint("https://x.com/admin/api/v1/users?id=5")
    assert {"admin", "api", "idor"} <= set(tags)


def test_scheme_and_host_do_not_change_classification():
    a = classify_endpoint("http://a.com/admin/login")
    b = classify_endpoint("https://b.com/admin/login")
    assert a == b and "auth" in a and "admin" in a


def test_a_boring_marketing_url_gets_no_tags():
    assert classify_endpoint("https://x.com/about/team") == []
