"""Demo mode — a public, genuinely read-only instance of the real product.

The demo is the actual application: the real Next.js frontend, the real API, real
seeded data. Nothing is mocked, so what a visitor clicks through is exactly what a
customer gets. The one difference is that it cannot be changed.

How read-only is enforced
-------------------------
By **HTTP method, in middleware, before routing** — not by a list of protected paths.

That direction matters. A path allowlist has to be updated every time a route is added,
and the failure mode of forgetting is a writable endpoint on a public demo. Denying
every unsafe method by default inverts it: a new route is read-only automatically, and
making something writable requires deliberately adding it to :data:`DEMO_WRITE_ALLOWED`
with a reason.

The frontend also disables its buttons, but that is cosmetic and is *not* the control.
Anyone can open devtools, re-enable a button, or simply `curl` the API. The middleware
is what actually holds, and ``tests/security/test_demo_mode.py`` proves it by attacking
the API directly rather than through the UI.

What else demo mode changes
---------------------------
Nothing. It does not alter business logic, hide fields, or fake responses — the demo
would stop being a demo of the product. The scanning workers are simply not deployed in
``docker-compose.demo.yml``, so a public instance can never launch a scan at anyone.
"""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

#: Methods that cannot change state. Everything else is refused in demo mode.
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

#: The only writes a demo visitor may perform, each with the reason it must work.
#: Adding to this list is a deliberate act — anything not here is refused.
DEMO_WRITE_ALLOWED: frozenset[str] = frozenset({
    "/auth/login",    # the demo shows the real login screen; visitors must get in
    "/auth/refresh",  # token refresh, or a long session dies mid-tour
})

DEMO_MESSAGE = (
    "This is the ExactSurface demo — it is read-only, so nothing can be created, "
    "changed or deleted. Everything you can see is real product data from a seeded "
    "scan. Deploy your own instance to run scans against domains you own."
)


class DemoReadOnlyMiddleware(BaseHTTPMiddleware):
    """Refuse every state-changing request when demo mode is on.

    Runs before routing and before any dependency, so it cannot be reached around by a
    route that forgets a guard, and it applies to routes that do not exist yet.
    """

    async def dispatch(self, request: Request, call_next):
        if request.method in SAFE_METHODS:
            return await call_next(request)

        path = request.url.path.rstrip("/") or "/"
        # Compare against the routed path without the API prefix a proxy may add, so
        # the check is the same whether the demo is served at / or behind /api.
        for allowed in DEMO_WRITE_ALLOWED:
            if path == allowed or path.endswith(allowed):
                return await call_next(request)

        return JSONResponse(
            status_code=403,
            content={"detail": DEMO_MESSAGE, "demo_mode": True},
        )
