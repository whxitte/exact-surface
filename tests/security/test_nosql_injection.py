"""NoSQL / operator-injection cannot widen a query's tenant scope (§8, §11).

Path and query parameters are typed ``str`` and are only ever used as equality
operands filtered *alongside* the authenticated ``tenant_id`` — which comes from
the verified token, never from client input. So an attacker sending a Mongo
operator (``{"$ne": null}``) as a program id or filter gets it treated as a
literal string: it matches nothing, and it can never turn into a real ``$ne``
that dumps another tenant's data.
"""

from __future__ import annotations

from core.hashing import finding_fingerprint
from core.models import Finding
from db.findings import FindingRepo
from tests.security.conftest import app_ctx, auth, make_program, run, signup  # noqa: F401

INJECTIONS = [
    '{"$ne": null}',
    '{"$gt": ""}',
    "*",
    "'; return true; //",
    "../../etc/passwd",
]


def test_operator_as_program_id_is_literal_404(app_ctx):  # noqa: F811
    client, _ = app_ctx
    tok = signup(client, email="inj@x.com", name="Inj")["access_token"]
    make_program(client, tok, "inj.com")  # a real program exists for this tenant
    for payload in INJECTIONS:
        r = client.get(f"/programs/{payload}", headers=auth(tok))
        assert r.status_code == 404, f"{payload!r} was not treated as a literal id"
        r2 = client.get(f"/programs/{payload}/findings", headers=auth(tok))
        assert r2.status_code == 404


def test_operator_in_filter_does_not_widen_results(app_ctx):  # noqa: F811
    """A severity filter carrying an operator returns nothing extra — it's an
    equality operand, so it simply matches no documents."""
    client, fake = app_ctx
    tok = signup(client, email="inj2@x.com", name="Inj2")
    token, tenant_id = tok["access_token"], tok["tenant_id"]
    pid = make_program(client, token, "inj2.com")
    run(
        FindingRepo(fake.collection("findings")).upsert(
            Finding(
                tenant_id=tenant_id,
                program_id=pid,
                fingerprint=finding_fingerprint(pid, "x", "https://inj2.com/x"),
                check_id="x",
                module="nuclei",
                location="https://inj2.com/x",
                name="only finding",
                severity="low",
            )
        )
    )
    # sanity: no filter → the one finding is returned
    assert len(client.get(f"/programs/{pid}/findings", headers=auth(token)).json()) == 1
    # operator-shaped severity filter → matches nothing (literal, not an operator)
    r = client.get(
        f"/programs/{pid}/findings", headers=auth(token), params={"severity": '{"$ne":"none"}'}
    )
    assert r.json() == []
