"""Workbench containment — the controls that keep our own tooling off the attack surface.

We sell attack-surface management. A test bench of ours that could be driven by a web
page the developer happens to have open would be the worst possible advertisement, so
these are not optional niceties and each one is asserted here.

Note what is NOT tested, because it does not exist: the workbench adds no route to the
ExactSurface API. It imports the modules and talks to Mongo in-process. There is nothing
on the product side for an outsider to guess — see ``test_product_api_has_no_devtools_
surface`` at the bottom, which asserts that stays true.
"""

from __future__ import annotations

import pathlib

import pytest
from fastapi.testclient import TestClient

from devtools import server

GOOD_HOST = f"127.0.0.1:{server.PORT}"
ORIGIN = f"http://127.0.0.1:{server.PORT}"


@pytest.fixture
def client():
    return TestClient(server.app, base_url=ORIGIN)


def _h(**extra) -> dict:
    return {"host": GOOD_HOST, **extra}


# -- the token ---------------------------------------------------------------


def test_no_token_is_404_everywhere():
    """404 rather than 401/403: a prober must not be able to tell that something is
    here and only the credential is missing."""
    c = TestClient(server.app, base_url=ORIGIN)
    for path in ("/", "/api/callables", "/api/runs", "/api/stages", "/api/programs"):
        assert c.get(path, headers=_h()).status_code == 404, path
    assert c.post("/api/call", json={}, headers=_h()).status_code == 404
    assert c.post("/api/stage", json={}, headers=_h()).status_code == 404


def test_wrong_token_is_404(client):
    bad = client.get("/api/callables", headers=_h(**{"x-workbench-token": "nope"}))
    assert bad.status_code == 404
    assert client.get("/api/callables?t=nope", headers=_h()).status_code == 404


def test_valid_token_works_as_header_or_query(client):
    assert client.get(
        "/api/callables", headers=_h(**{"x-workbench-token": server.TOKEN})
    ).status_code == 200
    assert client.get(f"/api/callables?t={server.TOKEN}", headers=_h()).status_code == 200


def test_token_is_long_random_and_not_persisted():
    assert len(server.TOKEN) >= 32
    # Never written to disk: a token in a file outlives the process that owned it.
    for path in pathlib.Path("devtools").rglob("*"):
        if path.is_file() and server.TOKEN in path.read_text(errors="ignore"):
            pytest.fail(f"the workbench token was written to {path}")


# -- DNS rebinding -----------------------------------------------------------


def test_foreign_host_header_is_rejected(client):
    """DNS rebinding: an attacker resolves their domain to 127.0.0.1 so the browser
    treats it as same-origin. The Host header is what gives that away."""
    for host in ("evil.com", f"evil.com:{server.PORT}", "attacker.internal"):
        r = client.get("/api/callables", headers={"host": host, "x-workbench-token": server.TOKEN})
        assert r.status_code == 404, host


def test_localhost_and_loopback_are_both_accepted(client):
    for host in (f"127.0.0.1:{server.PORT}", f"localhost:{server.PORT}"):
        r = client.get("/api/callables", headers={"host": host, "x-workbench-token": server.TOKEN})
        assert r.status_code == 200, host


# -- cross-site requests from a page the developer has open ------------------


def test_cross_site_browser_request_is_rejected_even_with_a_valid_token(client):
    """The core threat. A page on evil.com can make the browser POST to loopback; if
    that worked, visiting a website would let someone run a scanner from this machine.
    Rejected on Sec-Fetch-Site alone, which page JavaScript cannot forge."""
    r = client.post(
        "/api/call",
        json={"qualname": "modules.osint.typosquat:generate", "args": {"domain": "acme.com"}},
        headers=_h(**{"x-workbench-token": server.TOKEN, "sec-fetch-site": "cross-site"}),
    )
    assert r.status_code == 404


def test_foreign_origin_is_rejected(client):
    r = client.get(
        "/api/callables",
        headers=_h(**{"x-workbench-token": server.TOKEN, "origin": "https://evil.com"}),
    )
    assert r.status_code == 404


def test_same_origin_request_is_allowed(client):
    r = client.get(
        "/api/callables",
        headers=_h(
            **{"x-workbench-token": server.TOKEN, "origin": ORIGIN, "sec-fetch-site": "same-origin"}
        ),
    )
    assert r.status_code == 200


# -- what the bench may reach ------------------------------------------------


def test_only_discovered_callables_can_be_invoked(client):
    """The HTTP API must not be talkable into importing arbitrary modules."""
    from devtools import introspect

    for evil in ("os:system", "subprocess:run", "builtins:eval", "modules.exec:run_tool"):
        assert introspect.resolve(evil) is None, evil
        r = client.post(
            "/api/call",
            json={"qualname": evil, "args": {}},
            headers=_h(**{"x-workbench-token": server.TOKEN}),
        )
        assert r.status_code == 400, evil


def test_production_env_refuses_to_start(monkeypatch):
    """Not overridable by a flag: no configuration mistake may expose this."""
    from core.config import get_settings

    class _Prod:
        env = "prod"

    monkeypatch.setattr("core.config.get_settings", lambda: _Prod())
    with pytest.raises(SystemExit):
        server._assert_dev_only()
    get_settings.cache_clear() if hasattr(get_settings, "cache_clear") else None


# -- the product must stay clean of it ---------------------------------------


def test_product_api_has_no_devtools_surface():
    """The workbench must never gain a foothold in the shipped API. If someone later
    adds a convenience endpoint 'just for testing', this fails."""
    from api.main import app as product_app

    paths = {getattr(r, "path", "") for r in product_app.routes}
    for path in paths:
        low = path.lower()
        assert "devtool" not in low and "workbench" not in low, f"product exposes {path}"
        assert "run-module" not in low, (
            f"{path} lets a caller run one module on demand — that is workbench "
            "functionality and belongs in devtools/, not the product API"
        )


def test_no_product_source_file_imports_devtools():
    """The dependency only ever points one way: devtools imports the product, never
    the reverse. A product module importing devtools would ship it."""
    repo = pathlib.Path(__file__).resolve().parents[2]
    for pkg in ("api", "core", "db", "modules", "pipelines", "taskqueue", "daemon"):
        for path in (repo / pkg).rglob("*.py"):
            text = path.read_text(errors="ignore")
            assert "import devtools" not in text and "from devtools" not in text, (
                f"{path.relative_to(repo)} imports devtools"
            )
