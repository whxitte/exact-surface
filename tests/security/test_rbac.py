"""Group-based access control (§ access control / RBAC).

Signup makes an OWNER, who holds every permission and is the only principal that
can manage users and groups. A member has **no access at all** until the owner
puts them in a permission group; their effective permissions are the union of
their groups', resolved live from the DB on every request (so a change takes
effect immediately, not on next login).

These tests drive the real app end-to-end — the owner provisions members and
groups through the ``/members`` API, members log in through the real signing path,
and every assertion exercises the production dependency chain. They cover the
security-critical invariants:

* no access by default,
* a viewer group is read-only,
* ``programs.manage`` / ``settings.manage`` grant exactly their area and no more,
* member/group management is owner-only and non-delegable (no escalation),
* the owner account can't be re-grouped or deleted (a tenant always has an owner),
* groups are tenant-isolated, and revocation is immediate.
"""

from __future__ import annotations

from tests.security.conftest import app_ctx, auth, make_program, signup  # noqa: F401


# -- helpers -----------------------------------------------------------------
def _login(client, email: str, pw: str = "supersecret1") -> str:
    r = client.post("/auth/login", json={"email": email, "password": pw})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def _create_group(client, owner: str, name: str, perms: list[str]) -> str:
    r = client.post(
        "/members/groups", headers=auth(owner), json={"name": name, "permissions": perms}
    )
    assert r.status_code == 201, r.text
    return r.json()["group_id"]


def _create_member(client, owner: str, email: str, group_ids: list[str]) -> dict:
    r = client.post(
        "/members",
        headers=auth(owner),
        json={"email": email, "password": "supersecret1", "group_ids": group_ids},
    )
    assert r.status_code == 201, r.text
    return r.json()


def _member_in(client, owner: str, tid: str, email: str, perms: list[str] | None) -> str:
    """Provision a member (optionally in a one-off group with *perms*) and return
    a real login token for them. ``perms=None`` ⇒ no group at all."""
    group_ids = []
    if perms is not None:
        group_ids = [_create_group(client, owner, f"grp-{email}", perms)]
    _create_member(client, owner, email, group_ids)
    return _login(client, email)


def _owner(client, email: str = "owner@rbac.com", name: str = "RBAC") -> tuple[str, str]:
    o = signup(client, email=email, name=name)
    return o["access_token"], o["tenant_id"]


# -- no access by default ----------------------------------------------------
def test_new_member_has_no_access_by_default(app_ctx):  # noqa: F811
    client, _ = app_ctx
    owner, tid = _owner(client)
    make_program(client, owner, "rbac.com")
    member = _member_in(client, owner, tid, "nobody@rbac.com", perms=None)
    # Refused everywhere: reads and writes alike.
    assert client.get("/programs", headers=auth(member)).status_code == 403
    assert client.get("/stats", headers=auth(member)).status_code == 403
    assert client.get("/integrations", headers=auth(member)).status_code == 403


# -- viewer is read-only -----------------------------------------------------
def test_viewer_group_is_read_only(app_ctx):  # noqa: F811
    client, _ = app_ctx
    owner, tid = _owner(client)
    pid = make_program(client, owner, "rbac.com")
    viewer = _member_in(client, owner, tid, "viewer@rbac.com", perms=["view"])
    # Reads allowed.
    assert client.get("/programs", headers=auth(viewer)).status_code == 200
    assert client.get(f"/programs/{pid}/findings", headers=auth(viewer)).status_code == 200
    # Writes refused.
    assert client.post(f"/programs/{pid}/scan", headers=auth(viewer)).status_code == 403
    add = client.post("/programs", headers=auth(viewer), json={"apex_domain": "x.com"})
    assert add.status_code == 403
    assert (
        client.post(
            "/notifications",
            headers=auth(viewer),
            json={"name": "n", "type": "discord", "config": {"webhook_url": "https://d/h"}},
        ).status_code
        == 403
    )


# -- programs.manage: programs only ------------------------------------------
def test_programs_manage_operates_programs_not_settings(app_ctx):  # noqa: F811
    client, _ = app_ctx
    owner, tid = _owner(client)
    pid = make_program(client, owner, "rbac.com")
    pm = _member_in(client, owner, tid, "pm@rbac.com", perms=["programs.manage"])
    # manage implies view → can read, and can operate programs.
    assert client.get("/programs", headers=auth(pm)).status_code == 200
    assert client.post(f"/programs/{pid}/scan", headers=auth(pm)).status_code == 202
    # but settings are off-limits.
    assert (
        client.post(
            "/notifications",
            headers=auth(pm),
            json={"name": "n", "type": "discord", "config": {"webhook_url": "https://d/h"}},
        ).status_code
        == 403
    )
    assert client.post("/auth/api-keys", headers=auth(pm), json={"name": "k"}).status_code == 403


# -- settings.manage: settings only ------------------------------------------
def test_settings_manage_operates_settings_not_programs(app_ctx):  # noqa: F811
    client, _ = app_ctx
    owner, tid = _owner(client)
    pid = make_program(client, owner, "rbac.com")
    sm = _member_in(client, owner, tid, "sm@rbac.com", perms=["settings.manage"])
    # manage implies view → can read.
    assert client.get("/programs", headers=auth(sm)).status_code == 200
    # settings writes allowed.
    assert (
        client.post(
            "/notifications",
            headers=auth(sm),
            json={"name": "n", "type": "discord", "config": {"webhook_url": "https://d/h"}},
        ).status_code
        == 201
    )
    assert client.post("/auth/api-keys", headers=auth(sm), json={"name": "k"}).status_code == 201
    # program writes refused.
    assert client.post(f"/programs/{pid}/scan", headers=auth(sm)).status_code == 403
    assert client.delete(f"/programs/{pid}", headers=auth(sm)).status_code == 403


# -- member/group management is owner-only & non-delegable -------------------
def test_members_router_is_owner_only(app_ctx):  # noqa: F811
    client, _ = app_ctx
    owner, tid = _owner(client)
    # Even the strongest assignable permission set cannot reach the members API.
    strong = _member_in(client, owner, tid, "strong@rbac.com", perms=["settings.manage"])
    assert client.get("/members", headers=auth(strong)).status_code == 403
    assert client.get("/members/groups", headers=auth(strong)).status_code == 403
    assert client.get("/members/permissions", headers=auth(strong)).status_code == 403
    assert (
        client.post(
            "/members", headers=auth(strong), json={"email": "x@y.com", "password": "supersecret1"}
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/members/groups", headers=auth(strong), json={"name": "evil", "permissions": ["view"]}
        ).status_code
        == 403
    )


# -- owner can manage everything ---------------------------------------------
def test_owner_manages_members_and_groups(app_ctx):  # noqa: F811
    client, _ = app_ctx
    owner, tid = _owner(client)
    # A default Viewer group is seeded at signup.
    groups = client.get("/members/groups", headers=auth(owner)).json()
    assert any(g["is_default"] and g["permissions"] == ["view"] for g in groups)
    # Create → member appears with role member.
    m = _create_member(client, owner, "emp@rbac.com", [])
    assert m["role"] == "member"
    members = client.get("/members", headers=auth(owner)).json()
    assert {u["email"] for u in members} == {"owner@rbac.com", "emp@rbac.com"}
    # Re-group then remove.
    gid = _create_group(client, owner, "ops", ["programs.manage"])
    assert (
        client.patch(
            f"/members/{m['user_id']}", headers=auth(owner), json={"group_ids": [gid]}
        ).status_code
        == 200
    )
    assert client.delete(f"/members/{m['user_id']}", headers=auth(owner)).status_code == 204


# -- the owner account is protected ------------------------------------------
def test_owner_account_cannot_be_regrouped_or_deleted(app_ctx):  # noqa: F811
    client, _ = app_ctx
    owner, tid = _owner(client)
    members = client.get("/members", headers=auth(owner)).json()
    owner_uid = next(u["user_id"] for u in members if u["role"] == "owner")
    assert (
        client.patch(
            f"/members/{owner_uid}", headers=auth(owner), json={"group_ids": []}
        ).status_code
        == 409
    )
    assert client.delete(f"/members/{owner_uid}", headers=auth(owner)).status_code == 409


# -- no escalation via created role ------------------------------------------
def test_created_members_are_never_owner(app_ctx):  # noqa: F811
    client, _ = app_ctx
    owner, tid = _owner(client)
    m = _create_member(client, owner, "emp@rbac.com", [])
    assert m["role"] == "member"
    # A second signup with the same email is refused (email is globally unique).
    dup = client.post(
        "/members",
        headers=auth(owner),
        json={"email": "emp@rbac.com", "password": "supersecret1"},
    )
    assert dup.status_code == 409


# -- permission hygiene ------------------------------------------------------
def test_manage_permission_implies_view(app_ctx):  # noqa: F811
    client, _ = app_ctx
    owner, _tid = _owner(client)
    r = client.post(
        "/members/groups",
        headers=auth(owner),
        json={"name": "pm", "permissions": ["programs.manage", "bogus.perm"]},
    )
    assert r.status_code == 201
    perms = set(r.json()["permissions"])
    assert perms == {"view", "programs.manage"}  # unknown dropped, view implied


def test_unknown_group_id_is_rejected(app_ctx):  # noqa: F811
    client, _ = app_ctx
    owner, _tid = _owner(client)
    r = client.post(
        "/members",
        headers=auth(owner),
        json={"email": "e@rbac.com", "password": "supersecret1", "group_ids": ["g_nope"]},
    )
    assert r.status_code == 400


def test_default_viewer_group_cannot_be_deleted(app_ctx):  # noqa: F811
    client, _ = app_ctx
    owner, _tid = _owner(client)
    groups = client.get("/members/groups", headers=auth(owner)).json()
    default_gid = next(g["group_id"] for g in groups if g["is_default"])
    assert client.delete(f"/members/groups/{default_gid}", headers=auth(owner)).status_code == 409


# -- tenant isolation of groups ----------------------------------------------
def test_groups_are_tenant_isolated(app_ctx):  # noqa: F811
    client, _ = app_ctx
    owner_a, _ta = _owner(client, email="a@rbac.com", name="A")
    owner_b, _tb = _owner(client, email="b@rbac.com", name="B")
    gid_a = _create_group(client, owner_a, "a-grp", ["view"])
    # B cannot assign A's group to a B member.
    r = client.post(
        "/members",
        headers=auth(owner_b),
        json={"email": "bmem@rbac.com", "password": "supersecret1", "group_ids": [gid_a]},
    )
    assert r.status_code == 400
    # B doesn't even see A's group.
    b_groups = {g["group_id"] for g in client.get("/members/groups", headers=auth(owner_b)).json()}
    assert gid_a not in b_groups


# -- deleting a group detaches it from members -------------------------------
def test_deleting_group_detaches_members(app_ctx):  # noqa: F811
    client, _ = app_ctx
    owner, tid = _owner(client)
    gid = _create_group(client, owner, "temp", ["programs.manage"])
    m = _create_member(client, owner, "emp@rbac.com", [gid])
    assert gid in m["group_ids"]
    assert client.delete(f"/members/groups/{gid}", headers=auth(owner)).status_code == 204
    after = client.get("/members", headers=auth(owner)).json()
    emp = next(u for u in after if u["email"] == "emp@rbac.com")
    assert gid not in emp["group_ids"]


# -- revocation is immediate (live resolution) -------------------------------
def test_revocation_takes_effect_immediately(app_ctx):  # noqa: F811
    client, _ = app_ctx
    owner, tid = _owner(client)
    pid = make_program(client, owner, "rbac.com")
    gid = _create_group(client, owner, "ops", ["programs.manage"])
    m = _create_member(client, owner, "emp@rbac.com", [gid])
    token = _login(client, "emp@rbac.com")
    assert client.post(f"/programs/{pid}/scan", headers=auth(token)).status_code == 202
    # Remove all groups — same token, next request is already denied.
    client.patch(f"/members/{m['user_id']}", headers=auth(owner), json={"group_ids": []})
    assert client.post(f"/programs/{pid}/scan", headers=auth(token)).status_code == 403


# -- api keys inherit (only) the creator's live permissions ------------------
def test_api_key_is_bounded_by_creator_permissions(app_ctx):  # noqa: F811
    client, _ = app_ctx
    owner, tid = _owner(client)
    pid = make_program(client, owner, "rbac.com")
    sm = _member_in(client, owner, tid, "sm@rbac.com", perms=["settings.manage"])
    created = client.post("/auth/api-keys", headers=auth(sm), json={"name": "k"}).json()
    key = {"X-API-Key": created["api_key"]}
    # The key can read (view implied by settings.manage) …
    assert client.get("/programs", headers=key).status_code == 200
    # … but cannot run a scan — its creator has no programs.manage.
    assert client.post(f"/programs/{pid}/scan", headers=key).status_code == 403
    # and cannot mint an owner-scoped key (no escalation).
    esc = client.post("/auth/api-keys", headers=auth(sm), json={"name": "k2", "role": "owner"})
    assert esc.status_code == 403
