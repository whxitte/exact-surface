"""Plan-limit enforcement at the API (§13).

Free = 1 domain. A second domain is refused with 402; raising the tenant's plan
takes effect immediately (no restart, no re-auth). A program that falls outside
the allowance after a *downgrade* keeps its data but cannot be scanned.
"""

from __future__ import annotations

import asyncio

from fastapi.testclient import TestClient

from api.deps import get_domain_verifier, get_mongo_dep
from api.main import create_app
from api.rate_limit import limiter
from tests.fakes import FakeMongo


class StubVerifier:
    async def verify(self, apex, method, token):  # noqa: ANN001
        return True


def build():
    limiter.enabled = False
    fake = FakeMongo()
    app = create_app()
    app.dependency_overrides[get_mongo_dep] = lambda: fake
    app.dependency_overrides[get_domain_verifier] = lambda: StubVerifier()
    return TestClient(app), fake


def _run(coro):
    return asyncio.run(coro)


def _auth(t):
    return {"Authorization": f"Bearer {t}"}


def _signup(client, email="plan@x.com"):
    r = client.post(
        "/auth/signup", json={"email": email, "password": "supersecret1", "tenant_name": "P"}
    )
    assert r.status_code == 201
    return r.json()


def _set_plan(fake, tenant_id, plan):
    _run(fake.collection("tenants").update_one({"tenant_id": tenant_id}, {"$set": {"plan": plan}}))


def _create(client, token, apex):
    return client.post("/programs", headers=_auth(token), json={"apex_domain": apex})


def test_free_plan_allows_one_domain_then_402():
    client, _ = build()
    token = _signup(client)["access_token"]
    assert _create(client, token, "one.com").status_code == 201
    r = _create(client, token, "two.com")
    assert r.status_code == 402
    assert "1 domain" in r.json()["detail"]


def test_upgrade_takes_effect_immediately():
    client, fake = build()
    tok = _signup(client, email="up@x.com")
    token, tid = tok["access_token"], tok["tenant_id"]
    assert _create(client, token, "one.com").status_code == 201
    assert _create(client, token, "two.com").status_code == 402

    _set_plan(fake, tid, "pro")  # 5 domains — no restart, no new token
    assert _create(client, token, "two.com").status_code == 201
    assert _create(client, token, "three.com").status_code == 201


def test_enterprise_is_unlimited():
    client, fake = build()
    tok = _signup(client, email="ent@x.com")
    token, tid = tok["access_token"], tok["tenant_id"]
    _set_plan(fake, tid, "enterprise")
    for i in range(30):
        assert _create(client, token, f"d{i}.com").status_code == 201


def test_downgrade_blocks_scanning_the_over_quota_domain_but_keeps_data():
    client, fake = build()
    tok = _signup(client, email="down@x.com")
    token, tid = tok["access_token"], tok["tenant_id"]
    _set_plan(fake, tid, "pro")
    first = _create(client, token, "first.com").json()["program_id"]
    second = _create(client, token, "second.com").json()["program_id"]

    # make both scannable
    for pid in (first, second):
        client.post(f"/programs/{pid}/verify/request?method=dns_txt", headers=_auth(token))
        client.post(f"/programs/{pid}/verify/check", headers=_auth(token))
        client.post(f"/programs/{pid}/authorization", headers=_auth(token), json={})

    _set_plan(fake, tid, "free")  # downgrade → only the oldest (first.com) is covered

    assert client.post(f"/programs/{first}/scan", headers=_auth(token)).status_code == 202
    r = client.post(f"/programs/{second}/scan", headers=_auth(token))
    assert r.status_code == 402 and "outside that allowance" in r.json()["detail"]

    # nothing was deleted — the over-quota program is still readable
    assert client.get(f"/programs/{second}", headers=_auth(token)).status_code == 200
    assert len(client.get("/programs", headers=_auth(token)).json()) == 2
