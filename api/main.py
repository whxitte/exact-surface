"""FastAPI application factory (Phase A: health surface; Phase C: auth + routes).

``/healthz`` is a pure liveness probe — always 200 if the process is up, never
touches the DB (so a Mongo blip doesn't cause a restart loop). ``/readyz`` is the
readiness probe — it runs the real dependency checks and returns 503 if a critical
one fails. ``/metrics`` exposes the Prometheus registry.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from api.deps import require_router_access
from api.rate_limit import limiter
from api.routes import auth as auth_routes
from api.routes import integrations as integration_routes
from api.routes import members as member_routes
from api.routes import notifications as notification_routes
from api.routes import programs as program_routes
from api.routes import reports as report_routes
from api.routes import schedule as schedule_routes
from api.routes import stats as stats_routes
from api.ws import stream as ws_stream
from core.config import get_settings
from core.logging import configure_logging, logger
from core.metrics import REGISTRY
from core.permissions import PROGRAMS_MANAGE, SETTINGS_MANAGE, VIEW
from daemon.health import run_health_checks


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    configure_logging(level=settings.log_level, json_logs=settings.is_prod)
    settings.assert_prod_safe()
    from core.observability import init_sentry

    init_sentry(settings)
    logger.info("api starting (env={})", settings.env)
    # Best-effort DB connect + index bootstrap; readiness will report failures.
    try:
        from db.mongo import get_mongo

        mongo = get_mongo()
        await mongo.connect()
        await mongo.ensure_indexes()
    except Exception as exc:  # noqa: BLE001 - don't block liveness on a DB blip
        logger.warning("startup DB bootstrap skipped/failed: {}", exc)
    # Live activity bus (Redis pub/sub) powers /ws/activity. Best-effort: if Redis
    # is unavailable the websocket falls back to snapshot-only and the UI polls.
    try:
        from core.activity_bus import RedisActivityBus, set_bus

        set_bus(RedisActivityBus.connect(settings.redis_uri))
    except Exception as exc:  # noqa: BLE001
        logger.warning("activity bus unavailable: {}", exc)
    # Evaluate the subscription license now, then keep it fresh on an interval so an
    # expiry (or a renewal) takes effect without a restart. Enforcement is server-side
    # in the value routes; this just keeps the cached state current.
    license_task: asyncio.Task | None = None
    # Must be the SAME predicate the routes enforce with (api/deps.py ->
    # enforcement_active()). Guarding the *loader* on the raw settings flag while the
    # *gate* used enforcement_active() meant a release image enforced without ever
    # loading a licence: RELEASE_BUILD makes enforcement_active() true, the flag stays
    # false, so this block was skipped and the cached state remained MISSING. Every
    # customer would have been permanently read-only with a perfectly valid licence
    # installed, and nothing in the logs would say why.
    from core.entitlements import enforcement_active

    if enforcement_active():
        try:
            from core.entitlements import refresh as refresh_license
            from db.mongo import get_mongo

            await refresh_license(get_mongo())

            async def _license_loop() -> None:
                from core.entitlements import refresh as _refresh

                while True:
                    await asyncio.sleep(settings.license_check_interval_seconds)
                    try:
                        await _refresh(get_mongo())
                    except Exception as exc:  # noqa: BLE001 - never crash on a check
                        logger.warning("license refresh failed: {}", exc)

            license_task = asyncio.create_task(_license_loop())
        except Exception as exc:  # noqa: BLE001
            logger.warning("initial license evaluation failed (fail-closed): {}", exc)
    yield
    if license_task is not None:
        license_task.cancel()
    try:
        from core.activity_bus import get_bus, set_bus

        bus = get_bus()
        if bus is not None:
            await bus.close()
        set_bus(None)
    except Exception as exc:  # noqa: BLE001 - shutdown is best-effort
        logger.debug("activity bus close skipped: {}", exc)
    try:
        from db.mongo import get_mongo

        await get_mongo().close()
    except Exception as exc:  # noqa: BLE001 - shutdown is best-effort
        logger.debug("mongo close skipped: {}", exc)
    logger.info("api stopped")


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="ExactSurface API",
        version="0.1.0",
        description="Continuous external attack-surface intelligence — detection only.",
        lifespan=lifespan,
    )

    # Dev allows the local frontend; prod allows only explicitly-configured origins
    # (empty by default — the shipped stack is same-origin behind one proxy, so no
    # cross-origin access is granted to anyone). Never "*" with credentials.
    allowed = settings.cors_allowed_origins or (
        ["http://localhost:3000", "http://127.0.0.1:3000"] if not settings.is_prod else []
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Per-tenant rate limiting (slowapi).
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_handler)
    app.add_middleware(SlowAPIMiddleware)

    # Reject oversized request bodies up front (§8): our largest legitimate body is a
    # small JSON document, so a multi-MB payload is either a mistake or a memory-DoS
    # attempt. Enforced by declared Content-Length so we never buffer the body to find
    # out. 512 KiB is comfortably above any real request.
    max_body_bytes = 512 * 1024

    @app.middleware("http")
    async def _limit_body(request, call_next):
        cl = request.headers.get("content-length")
        if cl is not None:
            try:
                if int(cl) > max_body_bytes:
                    return Response(status_code=413, content="request body too large")
            except ValueError:
                return Response(status_code=400, content="invalid Content-Length")
        return await call_next(request)

    # Deployment watermark on every response — traceability for a leaked instance
    # (§ commercial). Cheap; the value is the licensee's customer id + build id.
    @app.middleware("http")
    async def _watermark(request, call_next):
        response = await call_next(request)
        try:
            from core.entitlements import watermark

            response.headers["X-ExactSurface-Instance"] = watermark()
        except Exception:  # noqa: BLE001, S110 - a header stamp must never break a response
            pass
        return response

    # Prometheus request metrics.
    @app.middleware("http")
    async def _metrics(request, call_next):
        response = await call_next(request)
        if settings.metrics_enabled:
            REGISTRY.inc(
                "exactsurface_http_requests_total",
                help="Total HTTP requests",
                method=request.method,
                status=str(response.status_code),
            )
        return response

    # Feature routers. Data routers carry a router-level RBAC gate (§ access control):
    # every route needs VIEW and every write needs the router's manage permission, so a
    # user with no permission group is refused everywhere and no new endpoint can ship
    # unguarded. The auth router is deliberately ungated — login/signup/verify/me must
    # be reachable by a user who has no permissions yet (so they can at least sign in
    # and see they have none). The members router is owner-only (see its own guard).
    def _gate(perm: str):
        return [Depends(require_router_access(perm))]

    app.include_router(auth_routes.router)
    app.include_router(member_routes.router)  # owner-only; guarded inside
    app.include_router(program_routes.router, dependencies=_gate(PROGRAMS_MANAGE))
    app.include_router(stats_routes.router, dependencies=_gate(VIEW))
    app.include_router(notification_routes.router, dependencies=_gate(SETTINGS_MANAGE))
    app.include_router(integration_routes.router, dependencies=_gate(SETTINGS_MANAGE))
    app.include_router(schedule_routes.router, dependencies=_gate(SETTINGS_MANAGE))
    app.include_router(report_routes.router, dependencies=_gate(VIEW))
    app.include_router(ws_stream.router)

    @app.get("/healthz")
    async def healthz() -> dict:
        return {"status": "ok"}

    @app.get("/readyz")
    async def readyz(response: Response) -> dict:
        report = await run_health_checks(check_services=True)
        critical = {"config", "scope_feeds", "mongo", "redis"}
        ready = report.critical_ok(critical)
        if not ready:
            response.status_code = 503
        return {
            "ready": ready,
            "checks": [{"name": c.name, "ok": c.ok, "detail": c.detail} for c in report.checks],
        }

    @app.get("/metrics")
    async def metrics() -> Response:
        return Response(content=REGISTRY.render(), media_type="text/plain; version=0.0.4")

    return app


def _rate_limit_handler(request, exc: RateLimitExceeded) -> Response:
    return Response("rate limit exceeded", status_code=429)


app = create_app()
