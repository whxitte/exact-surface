"""Structural guard: every data route requires authentication (§3.7, §8).

Rather than trusting that each new endpoint remembered its ``get_principal``
dependency, this test *enumerates every HTTP route on the app* and asserts that
calling it with no credentials never yields a 2xx. Public routes (health,
metrics, signup, login, docs) are an explicit allow-list — anything new that
should be public must be added here deliberately, which is the point: forgetting
auth on a new data route fails this test instead of shipping an open endpoint.
"""

from __future__ import annotations

from fastapi.routing import APIRoute

from tests.security.conftest import app_ctx  # noqa: F401

# Deliberately public — must be reviewed when extended.
PUBLIC_PATHS = {
    "/healthz",
    "/readyz",
    "/metrics",
    "/auth/signup",
    "/auth/login",
    # Public by design: the caller proves identity with the emailed one-time token,
    # not a session — the user has no credentials to verify with yet.
    "/auth/verify-email",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/docs/oauth2-redirect",
}

# Fill path params with a dummy value; a non-existent id must still require auth
# (auth is checked before the object is looked up).
_PARAM_STUB = "x"


def _fill(path: str) -> str:
    out = path
    while "{" in out:
        start = out.index("{")
        end = out.index("}", start)
        out = out[:start] + _PARAM_STUB + out[end + 1 :]
    return out


def _collect_routes(app):
    routes = []
    for r in app.app.routes if hasattr(app, "app") else app.routes:
        if isinstance(r, APIRoute):
            routes.append(r)
    return routes


def test_every_non_public_route_requires_auth(app_ctx):  # noqa: F811
    client, _ = app_ctx
    app = client.app
    offenders = []
    for route in [r for r in app.routes if isinstance(r, APIRoute)]:
        if route.path in PUBLIC_PATHS:
            continue
        method = next(iter(route.methods - {"HEAD", "OPTIONS"}), None)
        if method is None:
            continue
        url = _fill(route.path)
        # No Authorization / X-API-Key header.
        resp = client.request(method, url, json={} if method in {"POST", "PUT", "PATCH"} else None)
        if 200 <= resp.status_code < 300:
            offenders.append(f"{method} {route.path} → {resp.status_code}")
    assert not offenders, "Unauthenticated 2xx on protected route(s): " + "; ".join(offenders)


def test_protected_routes_return_401_not_403_or_500(app_ctx):  # noqa: F811
    """Missing creds → 401 specifically (not a leaky 403, not a crash). 422 is
    tolerated only where a required body/query is validated before the auth dep."""
    client, _ = app_ctx
    app = client.app
    bad = []
    for route in [r for r in app.routes if isinstance(r, APIRoute)]:
        if route.path in PUBLIC_PATHS:
            continue
        method = next(iter(route.methods - {"HEAD", "OPTIONS"}), None)
        if method is None:
            continue
        url = _fill(route.path)
        resp = client.request(method, url, json={} if method in {"POST", "PUT", "PATCH"} else None)
        if resp.status_code not in (401, 422):
            bad.append(f"{method} {route.path} → {resp.status_code}")
    assert not bad, "Protected routes with unexpected unauth status: " + "; ".join(bad)
