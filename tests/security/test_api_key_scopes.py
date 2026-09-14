"""API keys as the principal an agent holds: scoped, bounded, revocable, audited.

The threat model these cover is a non-human caller — a CI job, an integration, an AI
agent — whose key leaks or whose judgement is subverted. What it must be structurally
unable to do: exceed its creator, widen what may be scanned, mint a person, or act
without leaving a record. Every test here is a sentence from that list.
"""

from __future__ import annotations

from tests.security.conftest import app_ctx, auth, make_program, signup  # noqa: F401


def key_hdr(raw: str) -> dict[str, str]:
    return {"X-API-Key": raw}


def mint(client, token, scopes=None, name="agent") -> dict:
    r = client.post(
        "/auth/api-keys", headers=auth(token), json={"name": name, "scopes": scopes or []}
    )
    assert r.status_code == 201, r.text
    return r.json()


# -- default posture -----------------------------------------------------------
def test_a_key_minted_with_no_scopes_is_read_only(app_ctx):  # noqa: F811
    """The default is the least authority that does something useful."""
    client, _ = app_ctx
    tok = signup(client, email="o@x.com", name="X")["access_token"]
    pid = make_program(client, tok, "acme.com")
    key = mint(client, tok)
    assert key["scopes"] == ["read"]

    assert client.get("/programs", headers=key_hdr(key["api_key"])).status_code == 200
    assert (
        client.get(f"/programs/{pid}/findings", headers=key_hdr(key["api_key"])).status_code == 200
    )
    r = client.post(f"/programs/{pid}/scan", headers=key_hdr(key["api_key"]))
    assert r.status_code == 403
    assert "scans:run" in r.json()["detail"]


def test_a_scoped_key_can_do_exactly_what_it_was_given(app_ctx):  # noqa: F811
    client, _ = app_ctx
    tok = signup(client, email="o@x.com", name="X")["access_token"]
    pid = make_program(client, tok, "acme.com")
    key = mint(client, tok, scopes=["scans:run"])
    assert sorted(key["scopes"]) == ["read", "scans:run"]

    assert client.post(f"/programs/{pid}/scan", headers=key_hdr(key["api_key"])).status_code == 202
    # ...and not what it was not given.
    r = client.post(f"/programs/{pid}/monitoring?enabled=false", headers=key_hdr(key["api_key"]))
    assert r.status_code == 403 and "programs:write" in r.json()["detail"]


# -- a key can never be a way up -----------------------------------------------
def test_a_key_cannot_exceed_its_creator(app_ctx):  # noqa: F811
    """A member with view-only access asks for every scope. They get 'read'. The
    response says so rather than pretending — a client can see what it holds."""
    client, fake = app_ctx
    signup(client, email="owner@x.com", name="X")
    from core.models import Role
    from tests.security.conftest import run

    owner = run(fake.collection("users").find_one({"email": "owner@x.com"}))
    member_tok = client.post(
        "/auth/signup", json={"email": "m@x.com", "password": "supersecret1", "tenant_name": "M"}
    ).json()["access_token"]
    run(
        fake.collection("users").update_one(
            {"email": "m@x.com"},
            {"$set": {"tenant_id": owner["tenant_id"], "role": Role.MEMBER.value}},
        )
    )
    # Give the member settings.manage (needed to mint) but not programs.manage.
    from core.permissions import SETTINGS_MANAGE, VIEW

    gid = "g_scoped"
    run(
        fake.collection("groups").insert_one(
            {
                "tenant_id": owner["tenant_id"],
                "group_id": gid,
                "name": "settings-only",
                "permissions": [VIEW, SETTINGS_MANAGE],
                "is_default": False,
            }
        )
    )
    run(fake.collection("users").update_one({"email": "m@x.com"}, {"$set": {"group_ids": [gid]}}))
    # A fresh session for the moved user: the signup token was issued for a tenant
    # they no longer belong to.
    member_tok = client.post(
        "/auth/login", json={"email": "m@x.com", "password": "supersecret1"}
    ).json()["access_token"]

    key = mint(client, member_tok, scopes=["scans:run", "programs:write", "settings:write"])
    assert sorted(key["scopes"]) == ["read", "settings:write"], key["scopes"]


def test_scopes_are_rebounded_on_every_use_not_just_at_creation(app_ctx):  # noqa: F811
    """The creator loses a permission after minting. The key loses the matching scope
    at once — a key is never a snapshot of authority its creator no longer has."""
    client, fake = app_ctx
    tok = signup(client, email="o@x.com", name="X")["access_token"]
    pid = make_program(client, tok, "acme.com")
    key = mint(client, tok, scopes=["scans:run"])
    assert client.post(f"/programs/{pid}/scan", headers=key_hdr(key["api_key"])).status_code == 202

    # Demote the owner to a member with no groups: no permissions at all.
    from core.models import Role
    from tests.security.conftest import run

    run(
        fake.collection("users").update_one(
            {"email": "o@x.com"}, {"$set": {"role": Role.MEMBER.value, "group_ids": []}}
        )
    )
    assert client.post(f"/programs/{pid}/scan", headers=key_hdr(key["api_key"])).status_code == 403


# -- human-only actions --------------------------------------------------------
def test_no_scope_lets_a_key_widen_scope_or_mint_people(app_ctx):  # noqa: F811
    """An owner's key with every scope. The actions that widen what may be scanned or
    change who may act are refused anyway: those need a person in a session."""
    client, _ = app_ctx
    tok = signup(client, email="o@x.com", name="X")["access_token"]
    pid = make_program(client, tok, "acme.com")
    key = mint(
        client, tok, scopes=["scans:run", "programs:write", "playground:run", "settings:write"]
    )
    h = key_hdr(key["api_key"])

    refused = [
        ("post", f"/programs/{pid}/verify/request?method=dns_txt", None),
        ("post", f"/programs/{pid}/verify/check", None),
        ("post", f"/programs/{pid}/authorization", {}),
        ("post", f"/programs/{pid}/scan-config?scope_override=true", None),
        ("delete", f"/programs/{pid}", None),
        ("post", "/auth/api-keys", {"name": "child", "scopes": ["read"]}),
        ("post", "/members/groups", {"name": "g", "permissions": ["view"]}),
    ]
    for method, path, body in refused:
        r = (
            getattr(client, method)(path, headers=h, json=body)
            if body is not None
            else getattr(client, method)(path, headers=h)
        )
        assert r.status_code == 403, f"{method.upper()} {path} -> {r.status_code}: {r.text}"
        assert "interactive session" in r.json()["detail"], path

    # And the override really did not flip.
    assert client.get(f"/programs/{pid}", headers=auth(tok)).json()["scope_override"] is False


# -- revocation ----------------------------------------------------------------
def test_a_revoked_key_stops_working_immediately_and_stays_listed(app_ctx):  # noqa: F811
    client, _ = app_ctx
    tok = signup(client, email="o@x.com", name="X")["access_token"]
    key = mint(client, tok)
    assert client.get("/programs", headers=key_hdr(key["api_key"])).status_code == 200

    assert client.delete(f"/auth/api-keys/{key['key_id']}", headers=auth(tok)).status_code == 204
    r = client.get("/programs", headers=key_hdr(key["api_key"]))
    assert r.status_code == 401
    assert r.json()["detail"] == "invalid api key"  # same as unknown: nothing to probe

    listed = client.get("/auth/api-keys", headers=auth(tok)).json()
    assert [k["key_id"] for k in listed] == [key["key_id"]]
    assert listed[0]["revoked_at"] is not None
    assert "key_hash" not in listed[0] and "api_key" not in listed[0]


def test_a_key_cannot_revoke_keys(app_ctx):  # noqa: F811
    client, _ = app_ctx
    tok = signup(client, email="o@x.com", name="X")["access_token"]
    a = mint(client, tok, scopes=["settings:write"])
    b = mint(client, tok)
    r = client.delete(f"/auth/api-keys/{b['key_id']}", headers=key_hdr(a["api_key"]))
    assert r.status_code == 403
    assert client.get("/programs", headers=key_hdr(b["api_key"])).status_code == 200


def test_last_used_is_recorded(app_ctx):  # noqa: F811
    client, _ = app_ctx
    tok = signup(client, email="o@x.com", name="X")["access_token"]
    key = mint(client, tok)
    assert client.get("/auth/api-keys", headers=auth(tok)).json()[0]["last_used_at"] is None
    client.get("/programs", headers=key_hdr(key["api_key"]))
    assert client.get("/auth/api-keys", headers=auth(tok)).json()[0]["last_used_at"] is not None


# -- audit ---------------------------------------------------------------------
def test_every_mutating_call_by_a_key_is_audited_including_refusals(app_ctx):  # noqa: F811
    """The refused attempt is the more important record: a key repeatedly trying to
    widen its scope is exactly what an operator needs to be able to see afterwards."""
    client, _ = app_ctx
    tok = signup(client, email="o@x.com", name="X")["access_token"]
    pid = make_program(client, tok, "acme.com")
    key = mint(client, tok, scopes=["scans:run"])
    h = key_hdr(key["api_key"])

    client.post(f"/programs/{pid}/scan", headers=h)  # 202
    client.post(f"/programs/{pid}/scan-config?scope_override=true", headers=h)  # 403, human-only

    events = client.get("/audit", headers=auth(tok)).json()["events"]
    by_key = [e for e in events if e["key_id"] == key["key_id"]]
    actions = {(e["action"], e["status"]) for e in by_key}
    assert ("trigger_scan", 202) in actions
    assert ("set_scan_config", 403) in actions
    for e in by_key:
        assert e["actor_type"] == "apikey" and e["program_id"] == pid


def test_audit_never_records_a_password_or_a_raw_key(app_ctx):  # noqa: F811
    client, _ = app_ctx
    tok = signup(client, email="o@x.com", name="X", pw="hunter2-hunter2")["access_token"]
    key = mint(client, tok)
    dump = str(client.get("/audit", headers=auth(tok)).json())
    assert "hunter2" not in dump
    assert key["api_key"] not in dump


def test_audit_is_tenant_isolated_and_needs_settings_manage(app_ctx):  # noqa: F811
    client, _ = app_ctx
    a = signup(client, email="a@x.com", name="A")["access_token"]
    b = signup(client, email="b@y.com", name="B")["access_token"]
    make_program(client, a, "acme.com")
    b_events = client.get("/audit", headers=auth(b)).json()["events"]
    assert all(e["actor_id"] != "a" for e in b_events)
    assert not any(e["path"].startswith("/programs/") for e in b_events)
    # `read` means "read what your creator can read". The owner can read the audit
    # log, so their read-only key can too — and sees only their own tenant's events.
    key = mint(client, a)
    r = client.get("/audit", headers=key_hdr(key["api_key"]))
    assert r.status_code == 200
    assert all(e["tenant_id"] != "b" for e in r.json()["events"])


def test_the_scope_catalogue_says_what_the_caller_may_grant(app_ctx):  # noqa: F811
    client, _ = app_ctx
    tok = signup(client, email="o@x.com", name="X")["access_token"]
    cat = client.get("/auth/api-keys/scopes", headers=auth(tok)).json()["scopes"]
    assert {s["scope"] for s in cat} == {
        "read",
        "scans:run",
        "programs:write",
        "playground:run",
        "settings:write",
    }
    assert all(s["grantable"] for s in cat)  # owner


def test_a_key_minted_before_scopes_existed_keeps_what_it_had(app_ctx):  # noqa: F811
    """Upgrade safety. A pre-1.4.0 key document has no `scopes` field. It must keep
    every scope its creator can grant — the behaviour it always had — or every CI job
    that has been starting scans with one begins failing with 403 on upgrade day."""
    client, fake = app_ctx
    tok = signup(client, email="o@x.com", name="X")["access_token"]
    pid = make_program(client, tok, "acme.com")
    key = mint(client, tok)  # minted now: explicit ["read"]
    from tests.security.conftest import run

    # Turn it into a legacy document by removing the field, as an old row would lack it.
    run(
        fake.collection("apikeys").update_one({"key_id": key["key_id"]}, {"$unset": {"scopes": ""}})
    )
    doc = run(fake.collection("apikeys").find_one({"key_id": key["key_id"]}))
    assert "scopes" not in doc

    assert client.post(f"/programs/{pid}/scan", headers=key_hdr(key["api_key"])).status_code == 202
    me = client.get("/auth/me", headers=key_hdr(key["api_key"])).json()
    assert set(me["scopes"]) == {
        "read",
        "scans:run",
        "programs:write",
        "playground:run",
        "settings:write",
    }
    # ...but still nothing human-only.
    assert (
        client.post(
            f"/programs/{pid}/scan-config?scope_override=true", headers=key_hdr(key["api_key"])
        ).status_code
        == 403
    )
