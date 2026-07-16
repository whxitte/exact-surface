"""Shared fixtures/helpers for the security suite (§8).

All tests here drive the real FastAPI app through ``TestClient`` with an
in-memory ``FakeMongo`` and a stub domain verifier — no network, no DB. The
helpers mirror ``tests/e2e/test_api_flow.py`` so the adversarial tests exercise
exactly the code path a real client hits.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from fastapi.testclient import TestClient

from api.deps import get_domain_verifier, get_mongo_dep
from api.main import create_app
from api.rate_limit import limiter
from tests.fakes import FakeMongo


class StubVerifier:
    def __init__(self, result: bool = True) -> None:
        self.result = result

    async def verify(self, apex, method, token):  # noqa: ANN001
        return self.result


def run(coro: Any) -> Any:
    return asyncio.run(coro)


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture()
def app_ctx() -> tuple[TestClient, FakeMongo]:
    # The slowapi limiter is a process-global keyed by the constant TestClient IP,
    # so cumulative signups across the full suite would trip 60/min. Rate limiting
    # is exercised elsewhere; disable it here so these tests are hermetic.
    limiter.enabled = False
    fake = FakeMongo()
    app = create_app()
    app.dependency_overrides[get_mongo_dep] = lambda: fake
    app.dependency_overrides[get_domain_verifier] = lambda: StubVerifier(True)
    return TestClient(app), fake


def signup(client: TestClient, *, email: str, name: str, pw: str = "supersecret1") -> dict:
    r = client.post("/auth/signup", json={"email": email, "password": pw, "tenant_name": name})
    assert r.status_code == 201, r.text
    return r.json()


def make_program(client: TestClient, token: str, apex: str) -> str:
    """Create + verify + authorize a program, returning its id (ready to scan)."""
    pid = client.post("/programs", headers=auth(token), json={"apex_domain": apex}).json()[
        "program_id"
    ]
    client.post(f"/programs/{pid}/verify/request?method=dns_txt", headers=auth(token))
    client.post(f"/programs/{pid}/verify/check", headers=auth(token))
    client.post(f"/programs/{pid}/authorization", headers=auth(token), json={})
    return pid
