"""Email-verification flow + enforcement gate (§7 Phase C).

Drives the real endpoints with a captured ``LogEmailSender`` (no network) and a
FakeMongo. Covers: signup sends a verification email; the emailed token verifies
exactly once; invalid/expired tokens are refused; resend is rate-limited per
user; and — when ``require_email_verification`` is on — a program cannot be
created until the owner has verified.
"""

from __future__ import annotations

import re

from fastapi.testclient import TestClient

from api.deps import get_email_sender_dep, get_mongo_dep
from api.main import create_app
from api.rate_limit import limiter
from core.config import get_settings
from core.email import LogEmailSender
from tests.fakes import FakeMongo


def build():
    limiter.enabled = False  # hermetic: no cumulative signup rate-limit across the suite
    fake = FakeMongo()
    sender = LogEmailSender()
    app = create_app()
    app.dependency_overrides[get_mongo_dep] = lambda: fake
    app.dependency_overrides[get_email_sender_dep] = lambda: sender
    return TestClient(app), fake, sender


def _auth(t):
    return {"Authorization": f"Bearer {t}"}


def _signup(client, email="v@x.com", pw="supersecret1", name="V"):
    r = client.post("/auth/signup", json={"email": email, "password": pw, "tenant_name": name})
    assert r.status_code == 201, r.text
    return r.json()


def _token_from_last_email(sender: LogEmailSender) -> str:
    m = re.search(r"verify-email\?token=(\S+)", sender.sent[-1].text)
    assert m, "no verification link in email"
    return m.group(1)


def test_signup_sends_verification_email():
    client, _, sender = build()
    _signup(client, email="new@x.com")
    assert len(sender.sent) == 1
    assert sender.sent[0].to == "new@x.com"
    assert "verify-email?token=" in sender.sent[0].text


def test_verify_email_is_one_time():
    client, _, sender = build()
    tok = _signup(client, email="verify@x.com")
    vtoken = _token_from_last_email(sender)

    # before verifying, /me reports unverified
    me = client.get("/auth/me", headers=_auth(tok["access_token"])).json()
    assert me["email_verified"] is False and me["email"] == "verify@x.com"

    # verify → 200, /me flips to verified
    r = client.post("/auth/verify-email", json={"token": vtoken})
    assert r.status_code == 200 and r.json()["verified"] is True
    me = client.get("/auth/me", headers=_auth(tok["access_token"])).json()
    assert me["email_verified"] is True

    # the token is one-time — replaying it fails
    assert client.post("/auth/verify-email", json={"token": vtoken}).status_code == 400


def test_invalid_token_rejected():
    client, _, _ = build()
    assert client.post("/auth/verify-email", json={"token": "not-a-real-token"}).status_code == 400


def test_expired_token_rejected(monkeypatch):
    client, _, sender = build()
    # issue an already-expired token
    monkeypatch.setattr(get_settings(), "email_verification_ttl_seconds", -10)
    _signup(client, email="expired@x.com")
    vtoken = _token_from_last_email(sender)
    assert client.post("/auth/verify-email", json={"token": vtoken}).status_code == 400


def test_resend_is_cooloff_limited():
    client, _, sender = build()
    tok = _signup(client, email="resend@x.com")["access_token"]
    assert len(sender.sent) == 1
    # immediate resend is blocked by the per-user cool-off (default 60s)
    r = client.post("/auth/resend-verification", headers=_auth(tok))
    assert r.status_code == 429
    assert len(sender.sent) == 1  # no second email sent


def test_resend_after_cooloff_sends_again(monkeypatch):
    client, _, sender = build()
    monkeypatch.setattr(get_settings(), "email_resend_cooloff_seconds", 0)
    tok = _signup(client, email="resend2@x.com")["access_token"]
    r = client.post("/auth/resend-verification", headers=_auth(tok))
    assert r.status_code == 204
    assert len(sender.sent) == 2  # a fresh verification email went out


def test_resend_after_verified_is_noop():
    client, _, sender = build()
    tok = _signup(client, email="done@x.com")["access_token"]
    vtoken = _token_from_last_email(sender)
    client.post("/auth/verify-email", json={"token": vtoken})
    r = client.post("/auth/resend-verification", headers=_auth(tok))
    assert r.status_code == 204
    assert len(sender.sent) == 1  # already verified → nothing new sent


def test_program_creation_gated_when_enforcement_on(monkeypatch):
    client, _, sender = build()
    monkeypatch.setattr(get_settings(), "require_email_verification", True)
    tok = _signup(client, email="gate@x.com")["access_token"]

    # unverified → cannot create a program
    r = client.post("/programs", headers=_auth(tok), json={"apex_domain": "gate.com"})
    assert r.status_code == 403

    # verify, then creation is allowed
    client.post("/auth/verify-email", json={"token": _token_from_last_email(sender)})
    r2 = client.post("/programs", headers=_auth(tok), json={"apex_domain": "gate.com"})
    assert r2.status_code == 201


def test_enforcement_off_by_default_allows_creation():
    client, _, _ = build()
    tok = _signup(client, email="open@x.com")["access_token"]
    # default require_email_verification=False → unverified user can still create
    r = client.post("/programs", headers=_auth(tok), json={"apex_domain": "open.com"})
    assert r.status_code == 201
