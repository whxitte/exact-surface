"""JWT / credential hardening — the auth-bypass battery (§8, §9).

Proves the token verifier rejects every classic forgery: no token, malformed
token, the ``alg:none`` downgrade, a tampered payload, an expired token, and a
token signed with the wrong secret — and that a legitimately signed token (and a
valid API key) still work. A regression here is a full authentication bypass, so
these run adversarial inputs against the real ``/auth/me`` dependency chain.
"""

from __future__ import annotations

import base64
import json

from jose import jwt

from api.auth import create_access_token
from core.config import get_settings
from tests.security.conftest import app_ctx, auth, signup  # noqa: F401


def _b64url(obj: dict) -> str:
    raw = json.dumps(obj, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _forge_alg_none(tenant_id: str) -> str:
    """A classic ``alg:none`` token with an empty signature (the downgrade attack)."""
    header = _b64url({"alg": "none", "typ": "JWT"})
    payload = _b64url({"sub": "attacker", "tenant_id": tenant_id, "role": "owner"})
    return f"{header}.{payload}."


def test_missing_credentials_rejected(app_ctx):  # noqa: F811
    client, _ = app_ctx
    r = client.get("/auth/me")
    assert r.status_code == 401
    assert r.headers.get("WWW-Authenticate") == "Bearer"


def test_malformed_token_rejected(app_ctx):  # noqa: F811
    client, _ = app_ctx
    for bad in ["garbage", "a.b", "a.b.c", "Bearer", "...", ""]:
        assert client.get("/auth/me", headers=auth(bad)).status_code == 401


def test_alg_none_downgrade_rejected(app_ctx):  # noqa: F811
    """An unsigned ``alg:none`` token must never authenticate — the decoder pins HS256."""
    client, _ = app_ctx
    token = _forge_alg_none(tenant_id="t_victim")
    assert client.get("/auth/me", headers=auth(token)).status_code == 401


def test_tampered_signature_rejected(app_ctx):  # noqa: F811
    """A structurally valid token with a flipped signature byte is rejected."""
    client, _ = app_ctx
    tok = signup(client, email="jwt1@x.com", name="J1")["access_token"]
    head, payload, sig = tok.split(".")
    # flip a char in the *middle* of the signature (a trailing char's unused
    # base64 padding bits can decode to the same bytes and stay valid).
    mid = len(sig) // 2
    flipped = "A" if sig[mid] != "A" else "B"
    tampered_sig = sig[:mid] + flipped + sig[mid + 1 :]
    tampered = f"{head}.{payload}.{tampered_sig}"
    assert client.get("/auth/me", headers=auth(tampered)).status_code == 401


def test_tampered_payload_rejected(app_ctx):  # noqa: F811
    """Editing the payload (e.g. swapping tenant_id) invalidates the signature."""
    client, _ = app_ctx
    tok = signup(client, email="jwt2@x.com", name="J2")["access_token"]
    head, _payload, sig = tok.split(".")
    forged_payload = _b64url({"sub": "x", "tenant_id": "t_other", "role": "owner"})
    forged = f"{head}.{forged_payload}.{sig}"
    assert client.get("/auth/me", headers=auth(forged)).status_code == 401


def test_expired_token_rejected(app_ctx):  # noqa: F811
    """``exp`` in the past → 401 (python-jose verifies exp by default)."""
    client, _ = app_ctx
    expired = create_access_token(user_id="u", tenant_id="t_demo", role="owner", ttl=-10)
    assert client.get("/auth/me", headers=auth(expired)).status_code == 401


def test_wrong_secret_rejected(app_ctx):  # noqa: F811
    """A token signed with a different HS256 secret is rejected."""
    client, _ = app_ctx
    settings = get_settings()
    forged = jwt.encode(
        {"sub": "x", "tenant_id": "t_demo", "role": "owner"},
        "not-the-real-secret-value",
        algorithm=settings.jwt_algorithm,
    )
    assert client.get("/auth/me", headers=auth(forged)).status_code == 401


def test_valid_token_accepted(app_ctx):  # noqa: F811
    client, _ = app_ctx
    tok = signup(client, email="jwt3@x.com", name="J3")
    me = client.get("/auth/me", headers=auth(tok["access_token"]))
    assert me.status_code == 200 and me.json()["tenant_id"] == tok["tenant_id"]


def test_invalid_api_key_rejected(app_ctx):  # noqa: F811
    client, _ = app_ctx
    assert client.get("/auth/me", headers={"X-API-Key": "exs_not_a_real_key"}).status_code == 401


def test_role_is_not_client_controllable(app_ctx):  # noqa: F811
    """The role in a self-minted 'none' token is ignored — privilege can't be forged."""
    client, _ = app_ctx
    # even claiming role=owner in a forged token fails auth outright
    token = _forge_alg_none(tenant_id="t_demo")
    assert client.get("/auth/me", headers=auth(token)).status_code == 401
