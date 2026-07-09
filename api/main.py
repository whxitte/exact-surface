"""FastAPI application factory (Phase A: health surface; Phase C: auth + routes).

``/healthz`` is a pure liveness probe — always 200 if the process is up, never
touches the DB (so a Mongo blip doesn't cause a restart loop). ``/readyz`` is the
readiness probe — it runs the real dependency checks and returns 503 if a critical
one fails. ``/metrics`` exposes the Prometheus registry.
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from api.rate_limit import limiter
from api.routes import auth as auth_routes
from api.routes import integrations as integration_routes
from api.routes import notifications as notification_routes
from api.routes import programs as program_routes
from api.routes import reports as report_routes
from api.routes import stats as stats_routes
from api.ws import stream as ws_stream
from core.config import get_settings
from core.logging import configure_logging, logger
from daemon.health import run_health_checks
from daemon.metrics import REGISTRY


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
    yield
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
        title="Vantari API",
        version="0.1.0",
        description="Continuous external attack-surface intelligence — detection only.",
        lifespan=lifespan,
    )

    allowed = ["*"] if not settings.is_prod else []  # locked down per-deploy in prod
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

    # Prometheus request metrics.
    @app.middleware("http")
    async def _metrics(request, call_next):
        response = await call_next(request)
        if settings.metrics_enabled:
            REGISTRY.inc(
                "vantari_http_requests_total",
                help="Total HTTP requests",
                method=request.method,
                status=str(response.status_code),
            )
        return response

    # Feature routers.
    app.include_router(auth_routes.router)
    app.include_router(program_routes.router)
    app.include_router(stats_routes.router)
    app.include_router(notification_routes.router)
    app.include_router(integration_routes.router)
    app.include_router(report_routes.router)
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
