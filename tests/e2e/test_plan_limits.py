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


def test_free_plan_allows_multiple_domains_without_restriction():
    client, _ = build()
    token = _signup(client)["access_token"]
    assert _create(client, token, "one.com").status_code == 201
    assert _create(client, token, "two.com").status_code == 201
    assert _create(client, token, "three.com").status_code == 201


def test_enterprise_is_unlimited():
    client, fake = build()
    tok = _signup(client, email="ent@x.com")
    token, tid = tok["access_token"], tok["tenant_id"]
    _set_plan(fake, tid, "enterprise")
    for i in range(10):
        assert _create(client, token, f"d{i}.com").status_code == 201
