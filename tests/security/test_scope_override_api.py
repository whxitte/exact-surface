"""The scope-override switch, at the API boundary.

This is the one setting that lets ExactSurface reach an address the scope engine
would otherwise refuse, so its boundaries belong in the security suite rather than
beside the feature tests. What is asserted here: it defaults off, it round-trips,
it is per-program, it cannot be set on somebody else's program, and turning it on
does not disturb the authorization gate — which is a separate control and stays.
"""

from __future__ import annotations

from tests.security.conftest import app_ctx, auth, signup  # noqa: F401


def _verified_program(client, token, apex="acme.com"):
    pid = client.post("/programs", headers=auth(token), json={"apex_domain": apex}).json()[
        "program_id"
    ]
    client.post(f"/programs/{pid}/verify/request?method=dns_txt", headers=auth(token))
    client.post(f"/programs/{pid}/verify/check", headers=auth(token))
    return pid


def test_a_new_program_has_the_override_off(app_ctx):  # noqa: F811
    """Nothing acquires this by accident."""
    client, _ = app_ctx
    tok = signup(client, email="o@x.com", name="X")["access_token"]
    pid = _verified_program(client, tok)
    prog = client.get(f"/programs/{pid}", headers=auth(tok)).json()
    assert prog.get("scope_override", False) is False


def test_the_override_round_trips(app_ctx):  # noqa: F811
    client, _ = app_ctx
    tok = signup(client, email="o@x.com", name="X")["access_token"]
    pid = _verified_program(client, tok)

    r = client.post(f"/programs/{pid}/scan-config?scope_override=true", headers=auth(tok))
    assert r.status_code == 200, r.text
    assert r.json()["scope_override"] is True
    assert client.get(f"/programs/{pid}", headers=auth(tok)).json()["scope_override"] is True

    r = client.post(f"/programs/{pid}/scan-config?scope_override=false", headers=auth(tok))
    assert r.json()["scope_override"] is False


def test_each_switch_can_be_set_without_the_other(app_ctx):  # noqa: F811
    """Both query params are optional. The frontend flips one at a time, and a client
    that sends only one must not silently reset the other to its default."""
    client, _ = app_ctx
    tok = signup(client, email="o@x.com", name="X")["access_token"]
    pid = _verified_program(client, tok)

    client.post(f"/programs/{pid}/scan-config?scope_override=true", headers=auth(tok))
    r = client.post(f"/programs/{pid}/scan-config?scan_shared_infra=true", headers=auth(tok))
    assert r.json() == {
        "program_id": pid,
        "scan_shared_infra": True,
        "scope_override": True,
    }


def test_the_override_is_per_program(app_ctx):  # noqa: F811
    """Waiving the engine for one domain must not widen any other."""
    client, _ = app_ctx
    tok = signup(client, email="o@x.com", name="X")["access_token"]
    loud = _verified_program(client, tok, apex="loud.com")
    quiet = _verified_program(client, tok, apex="quiet.com")

    client.post(f"/programs/{loud}/scan-config?scope_override=true", headers=auth(tok))
    assert client.get(f"/programs/{quiet}", headers=auth(tok)).json()["scope_override"] is False


def test_another_tenant_cannot_set_the_override(app_ctx):  # noqa: F811
    """Cross-tenant is a 404 by design — it must not leak that the program exists,
    and it certainly must not flip this switch on somebody else's domain."""
    client, _ = app_ctx
    a = signup(client, email="a@x.com", name="A")["access_token"]
    b = signup(client, email="b@y.com", name="B")["access_token"]
    pid = _verified_program(client, a)

    r = client.post(f"/programs/{pid}/scan-config?scope_override=true", headers=auth(b))
    assert r.status_code == 404
    assert client.get(f"/programs/{pid}", headers=auth(a)).json()["scope_override"] is False


def test_the_override_does_not_waive_the_authorization_gate(app_ctx):  # noqa: F811
    """The two controls are separate and only one of them is being waived. An
    unverified program stays unscannable however this switch is set — otherwise the
    override would quietly become a way to skip domain verification too.
    """
    client, _ = app_ctx
    tok = signup(client, email="o@x.com", name="X")["access_token"]
    created = client.post("/programs", headers=auth(tok), json={"apex_domain": "unverified.com"})
    pid = created.json()["program_id"]

    client.post(f"/programs/{pid}/scan-config?scope_override=true", headers=auth(tok))
    assert client.post(f"/programs/{pid}/scan", headers=auth(tok)).status_code in (403, 409)
