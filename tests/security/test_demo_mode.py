"""Demo mode is read-only — proven by attacking the API, not the UI.

The demo is a public instance of the real product. The frontend disables its buttons,
but that is cosmetic: anyone can open devtools or `curl` the API directly. These tests
do exactly that. If any of them fail, a stranger can modify a public demo.

The enforcement is deny-by-method in middleware, so the important test is not "these
known routes are blocked" but **"a route nobody has written yet is blocked too"**.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from api.demo import DEMO_WRITE_ALLOWED, SAFE_METHODS
from api.deps import get_mongo_dep
from api.main import create_app
from core.config import get_settings
from tests.fakes import FakeMongo


@pytest.fixture
def demo_client(monkeypatch):
    monkeypatch.setenv("EXACTSURFACE_DEMO_MODE", "true")
    get_settings.cache_clear()
    fake = FakeMongo()
    app = create_app()
    app.dependency_overrides[get_mongo_dep] = lambda: fake
    yield TestClient(app), fake
    get_settings.cache_clear()


@pytest.fixture
def normal_client(monkeypatch):
    monkeypatch.setenv("EXACTSURFACE_DEMO_MODE", "false")
    get_settings.cache_clear()
    fake = FakeMongo()
    app = create_app()
    app.dependency_overrides[get_mongo_dep] = lambda: fake
    yield TestClient(app), fake
    get_settings.cache_clear()


# -- the attack surface a visitor actually has -------------------------------


@pytest.mark.parametrize(
    "method,path",
    [
        ("POST", "/programs"),
        ("DELETE", "/programs/prog_1"),
        ("POST", "/programs/prog_1/scan"),
        ("POST", "/programs/prog_1/bypass-403"),
        ("PUT", "/programs/prog_1/modules"),
        ("POST", "/programs/prog_1/schedule"),
        ("POST", "/programs/prog_1/verify/request"),
        ("POST", "/programs/prog_1/authorization"),
        ("POST", "/members"),
        ("POST", "/auth/signup"),
        ("POST", "/auth/api-keys"),
        ("POST", "/schedule/defaults"),
        ("POST", "/integrations"),
        ("POST", "/notifications/test"),
    ],
)
def test_every_write_route_is_refused(demo_client, method, path):
    client, _ = demo_client
    r = client.request(method, path, json={})
    assert r.status_code == 403, f"{method} {path} was not blocked"
    assert r.json().get("demo_mode") is True


def test_an_endpoint_that_does_not_exist_yet_is_also_refused(demo_client):
    """The point of denying by method rather than by path: a route added tomorrow is
    read-only without anyone remembering to protect it."""
    client, _ = demo_client
    for method in ("POST", "PUT", "PATCH", "DELETE"):
        r = client.request(method, "/some/route/invented/later", json={})
        assert r.status_code == 403, method
        assert r.json().get("demo_mode") is True


def test_blocked_before_auth_so_no_token_is_needed_to_be_refused(demo_client):
    """The refusal must not depend on authentication working — a write is refused
    whether the caller is anonymous, wrong, or a legitimately logged-in demo user."""
    client, _ = demo_client
    for headers in ({}, {"Authorization": "Bearer nonsense"}):
        r = client.post("/programs", json={"apex_domain": "victim.com"}, headers=headers)
        assert r.status_code == 403
        assert r.json().get("demo_mode") is True


def test_writes_leave_no_trace_in_the_database(demo_client):
    """Belt and braces: the request is refused *and* nothing was written."""
    client, fake = demo_client
    client.post("/auth/signup", json={
        "email": "attacker@evil.com", "password": "supersecret1", "tenant_name": "Evil",
    })
    client.post("/programs", json={"apex_domain": "victim.com"})
    import asyncio

    for collection in ("tenants", "users", "programs"):
        rows = asyncio.run(fake.collection(collection).find({}).to_list(None))
        assert rows == [], f"demo mode wrote to {collection}"


# -- what must still work ----------------------------------------------------


def test_reads_are_untouched(demo_client):
    client, _ = demo_client
    for path in ("/healthz", "/public-config"):
        assert client.get(path).status_code == 200


def test_login_still_works_because_the_demo_shows_the_real_login_screen(demo_client):
    """The demo deliberately includes the login page as part of the product tour, so
    exactly one write has to be allowed. It fails on credentials, not on demo mode."""
    client, _ = demo_client
    r = client.post("/auth/login", json={"email": "demo@exactsurface.com", "password": "x"})
    assert r.status_code != 403 or r.json().get("demo_mode") is not True


def test_the_write_allowlist_stays_minimal():
    """Every entry here is a hole in a public demo. If this fails, someone widened it —
    check that the new entry genuinely cannot be avoided."""
    assert DEMO_WRITE_ALLOWED == frozenset({"/auth/login", "/auth/refresh"})
    assert SAFE_METHODS == frozenset({"GET", "HEAD", "OPTIONS"})


def test_public_config_advertises_demo_mode(demo_client):
    client, _ = demo_client
    body = client.get("/public-config").json()
    assert body["demo_mode"] is True and body["demo_message"]


# -- and none of it leaks into a customer deployment -------------------------


def test_a_normal_instance_is_completely_unaffected(normal_client):
    """demo_mode is off by default and changes nothing when off. A customer's
    deployment must not inherit any of this."""
    client, _ = normal_client
    r = client.post("/auth/signup", json={
        "email": "real@customer.com", "password": "supersecret1", "tenant_name": "Real",
    })
    assert r.status_code == 201
    assert client.get("/public-config").json()["demo_mode"] is False


def test_demo_mode_defaults_to_off(monkeypatch):
    monkeypatch.delenv("EXACTSURFACE_DEMO_MODE", raising=False)
    get_settings.cache_clear()
    try:
        assert get_settings().demo_mode is False
    finally:
        get_settings.cache_clear()
