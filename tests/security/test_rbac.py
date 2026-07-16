"""Role-based access control on privileged operations (§9, authz).

Signup makes an OWNER. A ``MEMBER`` in the same tenant may read and operate
(list findings, trigger scans, manage notifications) but must NOT be able to
perform account-level or security-critical actions: minting API keys, deleting a
program, creating the legal scanning-authorization record, or managing
integration secrets. Member tokens are minted through the real signing path so
these exercise the production dependency chain.
"""

from __future__ import annotations

from api.auth import create_access_token
from tests.security.conftest import app_ctx, auth, make_program, signup  # noqa: F401


def _member_token(tenant_id: str) -> str:
    return create_access_token(user_id="u_member", tenant_id=tenant_id, role="member")


def _admin_token(tenant_id: str) -> str:
    return create_access_token(user_id="u_admin", tenant_id=tenant_id, role="admin")


def _owner_and_member(client):
    owner = signup(client, email="owner@rbac.com", name="RBAC")
    tid = owner["tenant_id"]
    pid = make_program(client, owner["access_token"], "rbac.com")
    return owner["access_token"], _member_token(tid), pid


def test_member_cannot_mint_api_keys(app_ctx):  # noqa: F811
    client, _ = app_ctx
    _owner, member, _pid = _owner_and_member(client)
    r = client.post("/auth/api-keys", headers=auth(member), json={"name": "x"})
    assert r.status_code == 403


def test_member_cannot_delete_program(app_ctx):  # noqa: F811
    client, _ = app_ctx
    _owner, member, pid = _owner_and_member(client)
    # 403 (role), not 404 — the program is in the member's own tenant.
    assert client.delete(f"/programs/{pid}", headers=auth(member)).status_code == 403


def test_member_cannot_create_authorization(app_ctx):  # noqa: F811
    client, _ = app_ctx
    _owner, member, pid = _owner_and_member(client)
    r = client.post(f"/programs/{pid}/authorization", headers=auth(member), json={})
    assert r.status_code == 403


def test_member_cannot_manage_integration_secrets(app_ctx):  # noqa: F811
    client, _ = app_ctx
    _owner, member, _pid = _owner_and_member(client)
    assert (
        client.put(
            "/integrations/github_token", headers=auth(member), json={"value": "ghp_x"}
        ).status_code
        == 403
    )
    assert client.delete("/integrations/github_token", headers=auth(member)).status_code == 403


def test_member_can_still_operate(app_ctx):  # noqa: F811
    """RBAC restricts privileged ops only — a member can read and run scans."""
    client, _ = app_ctx
    _owner, member, pid = _owner_and_member(client)
    # read findings (empty but 200, not 403)
    assert client.get(f"/programs/{pid}/findings", headers=auth(member)).status_code == 200
    # trigger a scan (program is verified+authorized) — 202, not 403
    assert client.post(f"/programs/{pid}/scan", headers=auth(member)).status_code == 202
    # manage a notification channel
    created = client.post(
        "/notifications",
        headers=auth(member),
        json={"name": "ops", "type": "discord", "config": {"webhook_url": "https://d/h"}},
    )
    assert created.status_code == 201


def test_owner_can_perform_privileged_ops(app_ctx):  # noqa: F811
    client, _ = app_ctx
    owner, _member, pid = _owner_and_member(client)
    assert (
        client.post("/auth/api-keys", headers=auth(owner), json={"name": "ci"}).status_code == 201
    )
    assert client.delete(f"/programs/{pid}", headers=auth(owner)).status_code == 204


def test_admin_cannot_mint_owner_key_privilege_escalation(app_ctx):  # noqa: F811
    """An admin may create keys, but not one scoped above its own role."""
    client, _ = app_ctx
    owner = signup(client, email="adm@rbac.com", name="Adm")
    admin = _admin_token(owner["tenant_id"])
    # admin minting a member key is fine
    assert (
        client.post(
            "/auth/api-keys", headers=auth(admin), json={"name": "k", "role": "member"}
        ).status_code
        == 201
    )
    # admin minting an OWNER key is refused (no privilege escalation)
    esc = client.post("/auth/api-keys", headers=auth(admin), json={"name": "k2", "role": "owner"})
    assert esc.status_code == 403
