"""The API validates every externally-supplied value server-side (§8, §11).

Frontend checks don't exist as far as the server is concerned — these drive the real
app with crafted bodies (as curl/Burp would) and assert the server rejects them with a
422/413 rather than persisting or acting on them. The standout case is SSRF: a webhook
channel must not be allowed to point at the cloud-metadata endpoint or an internal host.
"""

from __future__ import annotations

from tests.security.conftest import app_ctx, auth, signup  # noqa: F401


def _token(client) -> str:
    return signup(client, email="val@x.com", name="Val")["access_token"]


# -- program domain ----------------------------------------------------------
def test_bogus_apex_domain_is_rejected(app_ctx):  # noqa: F811
    client, _ = app_ctx
    tok = _token(client)
    for bad in ["http://evil.com", "example.com/path", "10.0.0.1", "a b.com", "notadomain"]:
        r = client.post("/programs", headers=auth(tok), json={"apex_domain": bad})
        assert r.status_code == 422, f"{bad!r} should be rejected"


def test_valid_domain_accepted_and_normalised(app_ctx):  # noqa: F811
    client, _ = app_ctx
    tok = _token(client)
    r = client.post("/programs", headers=auth(tok), json={"apex_domain": "Example.COM"})
    assert r.status_code == 201
    assert r.json()["apex_domain"] == "example.com"


def test_invalid_excluded_cidr_rejected(app_ctx):  # noqa: F811
    client, _ = app_ctx
    tok = _token(client)
    r = client.post(
        "/programs",
        headers=auth(tok),
        json={"apex_domain": "ok.com", "excluded_cidrs": ["not-a-cidr"]},
    )
    assert r.status_code == 422


def test_too_many_excluded_hosts_rejected(app_ctx):  # noqa: F811
    client, _ = app_ctx
    tok = _token(client)
    r = client.post(
        "/programs",
        headers=auth(tok),
        json={"apex_domain": "ok.com", "excluded_hosts": [f"h{i}.ok.com" for i in range(600)]},
    )
    assert r.status_code == 422


# -- notification SSRF -------------------------------------------------------
def test_webhook_to_cloud_metadata_is_rejected(app_ctx):  # noqa: F811
    """The server POSTs to a webhook URL on every alert — it must refuse an internal
    target at creation, so an attacker can't turn alerts into SSRF."""
    client, _ = app_ctx
    tok = _token(client)
    for url in [
        "http://169.254.169.254/latest/meta-data/",
        "https://127.0.0.1/x",
        "http://10.0.0.5/hook",
        "ftp://evil/x",
    ]:
        r = client.post(
            "/notifications",
            headers=auth(tok),
            json={"name": "x", "type": "webhook", "config": {"url": url}},
        )
        assert r.status_code == 422, f"{url!r} should be rejected"


def test_discord_webhook_internal_rejected(app_ctx):  # noqa: F811
    client, _ = app_ctx
    tok = _token(client)
    r = client.post(
        "/notifications",
        headers=auth(tok),
        json={"name": "d", "type": "discord", "config": {"webhook_url": "http://127.0.0.1/x"}},
    )
    assert r.status_code == 422


def test_public_webhook_is_accepted(app_ctx):  # noqa: F811
    client, _ = app_ctx
    tok = _token(client)
    r = client.post(
        "/notifications",
        headers=auth(tok),
        json={
            "name": "ok",
            "type": "discord",
            "config": {"webhook_url": "https://discord.com/api/webhooks/1/abc"},
        },
    )
    assert r.status_code == 201


def test_malicious_telegram_token_rejected(app_ctx):  # noqa: F811
    """A token like ``x@169.254.169.254/`` would rewrite the request host."""
    client, _ = app_ctx
    tok = _token(client)
    r = client.post(
        "/notifications",
        headers=auth(tok),
        json={
            "name": "tg",
            "type": "telegram",
            "config": {"bot_token": "x@169.254.169.254/", "chat_id": "123"},
        },
    )
    assert r.status_code == 422


# -- body size ---------------------------------------------------------------
def test_oversized_body_is_rejected_with_413(app_ctx):  # noqa: F811
    client, _ = app_ctx
    tok = _token(client)
    big = "a" * (600 * 1024)
    r = client.post("/programs", headers=auth(tok), json={"apex_domain": "ok.com", "note": big})
    assert r.status_code == 413


# -- self-hosted signup lock -------------------------------------------------
def test_public_signup_closes_after_the_first_org_in_prod(app_ctx, monkeypatch):  # noqa: F811
    """A self-hosted instance serves ONE organisation. The first signup bootstraps the
    owner; after that, a stranger who reaches the login page must not be able to create
    their own tenant on the customer's server."""
    from core.config import get_settings

    client, _ = app_ctx
    # First signup always works — that's how the owner is created.
    signup(client, email="owner@self.host", name="Self Hosted")

    monkeypatch.setattr(get_settings(), "env", "prod")
    monkeypatch.setattr(get_settings(), "allow_public_signup", False)

    r = client.post(
        "/auth/signup",
        json={"email": "stranger@evil.com", "password": "supersecret1", "tenant_name": "Evil"},
    )
    assert r.status_code == 403
    assert "already set up" in r.json()["detail"]


def test_operator_can_opt_into_multi_tenant_signup(app_ctx, monkeypatch):  # noqa: F811
    """The lock is a safe default, not a hard limit — a multi-tenant deployment opts in."""
    from core.config import get_settings

    client, _ = app_ctx
    signup(client, email="a@multi.host", name="A")
    monkeypatch.setattr(get_settings(), "env", "prod")
    monkeypatch.setattr(get_settings(), "allow_public_signup", True)

    r = client.post(
        "/auth/signup",
        json={"email": "b@multi.host", "password": "supersecret1", "tenant_name": "B"},
    )
    assert r.status_code == 201
