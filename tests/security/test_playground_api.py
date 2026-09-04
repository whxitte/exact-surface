"""Playground API: catalogue, workflow CRUD, validation, and the run gate.

Drives the real app through TestClient with an in-memory Mongo. The point of putting
these in the *security* suite rather than beside the unit tests is the last group: the
Playground can start real scans and (for an owner) can waive the §9b authorization
check, so its boundaries are adversarial surface, not just feature surface.
"""

from __future__ import annotations

from tests.security.conftest import app_ctx, auth, signup  # noqa: F401


def _target_graph(hosts: str = "example.com") -> dict:
    return {
        "nodes": {
            "t": {"type": "source:target", "params": {"hosts": hosts}},
            "o": {"type": "output:view"},
        },
        "edges": [{"source": "t", "sourceHandle": "hosts", "target": "o", "targetHandle": "value"}],
    }


# -- catalogue ---------------------------------------------------------------
def test_catalogue_lists_every_module_as_a_node(app_ctx):  # noqa: F811
    from core import modules as registry

    client, _ = app_ctx
    tok = signup(client, email="o@x.com", name="X")["access_token"]
    r = client.get("/playground/nodes", headers=auth(tok))
    assert r.status_code == 200
    keys = {n["key"] for n in r.json()["nodes"]}
    for module in registry.MODULES:
        assert f"pipeline:{module.name}" in keys, f"{module.name} missing from the catalogue"


def test_catalogue_requires_authentication(app_ctx):  # noqa: F811
    client, _ = app_ctx
    assert client.get("/playground/nodes").status_code in (401, 403)


# -- workflow CRUD -----------------------------------------------------------
def test_save_list_and_delete_a_workflow(app_ctx):  # noqa: F811
    client, _ = app_ctx
    tok = signup(client, email="o@x.com", name="X")["access_token"]

    r = client.put(
        "/playground/workflows/wf1",
        headers=auth(tok),
        json={"name": "My canvas", "graph": _target_graph()},
    )
    assert r.status_code == 200, r.text
    assert r.json()["name"] == "My canvas"

    listed = client.get("/playground/workflows", headers=auth(tok)).json()["workflows"]
    assert [w["workflow_id"] for w in listed] == ["wf1"]

    assert client.delete("/playground/workflows/wf1", headers=auth(tok)).status_code == 204
    assert client.get("/playground/workflows", headers=auth(tok)).json()["workflows"] == []


def test_a_broken_graph_is_refused_on_save_with_the_node_named(app_ctx):  # noqa: F811
    """Rejecting at save time means the user sees the error while the canvas is still
    in front of them, instead of discovering it on a run minutes later."""
    client, _ = app_ctx
    tok = signup(client, email="o@x.com", name="X")["access_token"]
    r = client.put(
        "/playground/workflows/bad",
        headers=auth(tok),
        json={"name": "Broken", "graph": {"nodes": {"o": {"type": "output:view"}}, "edges": []}},
    )
    assert r.status_code == 422
    assert r.json()["detail"]["node"] == "o"


def test_workflows_are_tenant_isolated(app_ctx):  # noqa: F811
    """Another tenant's canvas must be invisible, not merely unauthorised."""
    client, _ = app_ctx
    a = signup(client, email="a@x.com", name="A")["access_token"]
    b = signup(client, email="b@y.com", name="B")["access_token"]

    client.put(
        "/playground/workflows/secret",
        headers=auth(a),
        json={"name": "A's canvas", "graph": _target_graph()},
    )
    assert client.get("/playground/workflows", headers=auth(b)).json()["workflows"] == []


# -- validation endpoint -----------------------------------------------------
def test_validate_reports_a_cycle_without_running_anything(app_ctx):  # noqa: F811
    client, _ = app_ctx
    tok = signup(client, email="o@x.com", name="X")["access_token"]
    graph = {
        "nodes": {"p": {"type": "pipeline:probe"}, "c": {"type": "pipeline:crawl"}},
        "edges": [
            {"source": "p", "sourceHandle": "hosts", "target": "c", "targetHandle": "targets"},
            {"source": "c", "sourceHandle": "hosts", "target": "p", "targetHandle": "targets"},
        ],
    }
    r = client.post("/playground/validate", headers=auth(tok), json={"graph": graph})
    assert r.status_code == 200
    assert r.json()["ok"] is False
    assert "loops back" in r.json()["message"]


def test_validate_accepts_a_good_graph_and_returns_run_order(app_ctx):  # noqa: F811
    client, _ = app_ctx
    tok = signup(client, email="o@x.com", name="X")["access_token"]
    r = client.post("/playground/validate", headers=auth(tok), json={"graph": _target_graph()})
    assert r.json() == {"ok": True, "order": ["t", "o"]}


# -- run ---------------------------------------------------------------------
def test_run_requires_a_program_to_store_results_in(app_ctx):  # noqa: F811
    """Pipelines persist findings and assets; a run with nowhere to put them would
    scatter data under a program that does not exist."""
    client, _ = app_ctx
    tok = signup(client, email="o@x.com", name="X")["access_token"]
    r = client.post("/playground/run", headers=auth(tok), json={"graph": _target_graph()})
    assert r.status_code == 422
    assert "program" in r.json()["detail"].lower()


def test_owner_may_run_a_target_node(app_ctx):  # noqa: F811
    """The first account is the owner, so the free-form waiver applies to them —
    the concession SECURITY.md §2b already makes explicit for the operator."""
    client, _ = app_ctx
    tok = signup(client, email="o@x.com", name="X")["access_token"]
    r = client.post(
        "/playground/run",
        headers=auth(tok),
        json={"program_id": "p1", "graph": _target_graph()},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["freeform"] is True
    assert body["nodes"]["t"]["status"] == "success"
    assert body["nodes"]["o"]["status"] == "success"


def test_a_member_cannot_run_a_target_node(app_ctx):  # noqa: F811
    """The whole justification for the waiver is that it grants an owner nothing they
    could not already do by editing Mongo. A member has no such access, so for them
    this would be a genuine escalation — 403, with a reason they can act on."""
    client, fake = app_ctx
    signup(client, email="owner@x.com", name="X")

    from core.models import Role
    from tests.security.conftest import run

    # Promote a second user into the same tenant as a plain member.
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

    r = client.post(
        "/playground/run",
        headers=auth(member_tok),
        json={"program_id": "p1", "graph": _target_graph()},
    )
    assert r.status_code == 403
    assert "owner" in r.json()["detail"].lower()


def test_run_refuses_a_graph_that_does_not_validate(app_ctx):  # noqa: F811
    client, _ = app_ctx
    tok = signup(client, email="o@x.com", name="X")["access_token"]
    r = client.post(
        "/playground/run",
        headers=auth(tok),
        json={
            "program_id": "p1",
            "graph": {"nodes": {"x": {"type": "pipeline:not_real"}}, "edges": []},
        },
    )
    assert r.status_code == 422
    assert r.json()["detail"]["node"] == "x"
