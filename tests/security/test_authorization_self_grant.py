"""A tenant must not be able to self-grant aggressive scanning (§9b step 3).

The P0 regression guard. Previously ``AuthorizationCreate.ip_scope`` accepted
full entries — ip_class, action_set and confirmed_via included — and stored them
verbatim, so a client could declare any CIDR "dedicated" and unlock port scanning
plus aggressive nuclei against infrastructure they don't own (point a subdomain of
a domain you *do* control at any IP, then declare that IP's block yours).

The API now accepts only *requested* CIDR strings and records them as pending /
HTTP-layer-only. Promotion to DEDICATED happens solely on the worker, after
asnmap confirms the range against the verified apex's ASN.
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


def test_requested_cidrs_are_recorded_pending_not_dedicated(app_ctx):  # noqa: F811
    client, _ = app_ctx
    token = signup(client, email="az@x.com", name="AZ")["access_token"]
    pid = _verified_program(client, token)

    r = client.post(
        f"/programs/{pid}/authorization",
        headers=auth(token),
        json={"ip_scope": ["8.8.8.0/24", "45.55.0.0/16"]},
    )
    assert r.status_code == 201
    entries = r.json()["ip_scope"]
    assert len(entries) == 2
    for e in entries:
        assert e["ip_class"] != "dedicated", "API granted dedicated from client input"
        assert e["confirmed_via"] == "pending"
        assert "port_scan" not in e["action_set"]


def test_client_cannot_assert_ip_class_or_confirmed_via(app_ctx):  # noqa: F811
    """The old exploit payload is now a schema error — the fields don't exist."""
    client, _ = app_ctx
    token = signup(client, email="az2@x.com", name="AZ2")["access_token"]
    pid = _verified_program(client, token)

    r = client.post(
        f"/programs/{pid}/authorization",
        headers=auth(token),
        json={
            "ip_scope": [
                {
                    "cidr": "8.8.8.0/24",
                    "ip_class": "dedicated",
                    "action_set": ["port_scan", "active_scan"],
                    "confirmed_via": "whois:AS15169",
                }
            ]
        },
    )
    assert r.status_code == 422  # rejected outright, not silently trusted


def test_authorization_read_back_never_shows_dedicated(app_ctx):  # noqa: F811
    client, _ = app_ctx
    token = signup(client, email="az3@x.com", name="AZ3")["access_token"]
    pid = _verified_program(client, token)
    client.post(
        f"/programs/{pid}/authorization",
        headers=auth(token),
        json={"ip_scope": ["1.1.1.0/24"]},
    )
    got = client.get(f"/programs/{pid}/authorization", headers=auth(token)).json()
    assert all(e["ip_class"] != "dedicated" for e in got["ip_scope"])
