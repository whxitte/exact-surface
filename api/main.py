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

from core.config import get_settings
from core.logging import configure_logging, logger
from daemon.health import run_health_checks
from daemon.metrics import REGISTRY


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    configure_logging(json_logs=settings.is_prod)
    settings.assert_prod_safe()
    logger.info("api starting (env={})", settings.env)
    # Best-effort DB connect + index bootstrap; readiness will report failures.
    try:
        from db.mongo import get_mongo

        mongo = get_mongo()
        await mongo.connect()
        await mongo.ensure_indexes()
    except Exception as exc:  # noqa: BLE001 - don't block liveness on a DB blip
        logger.warning("startup DB bootstrap skipped/failed: {}", exc)
    yield
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


app = create_app()
