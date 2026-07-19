"""On-demand 403/401-bypass runner (module: http_bypass).

This is **not** a pipeline phase — it never runs on a schedule and is not wired into
the cascade. It runs only when a user clicks "Try 403 bypass" in the Endpoints tab. It
still reuses the ScanRun + live-log plumbing so its progress shows in the Activity feed
exactly like a scan ("trying X-Original-URL …", "BYPASS: /admin via …").

Safety: it makes active HTTP requests, so it enforces the same gate as any scan — a
current authorization (§9b) and per-endpoint scope evaluation (HTTP_PROBE must be
permitted) — and paces every request through the shared politeness limiter (§3.8b). The
technique matrix is detection-only (safe methods, redirects off, host never changed);
see :mod:`modules.http_bypass`.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from core.errors import AuthorizationRequired
from core.logging import bind_context, logger
from core.models import ScanRun, ScanStatus
from core.ratelimit import PolitenessLimiter
from core.scope import Action, ScopeEngine
from core.tenant import TenantContext
from db.assets import AssetRepo
from db.audit import ScanRunRepo
from db.authorizations import AuthorizationRepo
from db.endpoints import EndpointRepo
from db.programs import ProgramRepo
from modules.http_bypass import default_probe, run_bypass
from pipelines.orchestrate import build_program_scope

#: Only these baseline statuses are worth attempting a bypass against.
_FORBIDDEN = (401, 403)
#: Bound how many forbidden endpoints one run will hammer, so an accidental huge
#: surface can't turn into thousands of paced requests. The user can re-run.
MAX_ENDPOINTS_PER_RUN = 50


def _throttled_probe(probe, limiter: PolitenessLimiter):
    """Pace an injected ``probe(url, method, headers)`` through the limiter, keyed by
    host — the same politeness ceiling every other active module uses (§3.8b)."""

    async def _p(url: str, method: str, headers: dict[str, str]):
        await limiter.acquire(urlsplit(url).hostname or url)
        return await probe(url, method, headers)

    return _p


def _auth_current(auth: dict | None) -> bool:
    return bool(auth and auth.get("apex_verified") and not auth.get("revoked"))


async def run_bypass_403(
    *,
    mongo: Any,
    engine: ScopeEngine,
    scope,
    tenant: TenantContext,
    program_id: str,
    targets: tuple[str, ...] = (),
    limiter: PolitenessLimiter | None = None,
    probe=default_probe,
) -> dict:
    """Attempt a 403/401 bypass on the program's forbidden endpoints (or the specific
    ``targets`` fingerprints). Records results on each endpoint and returns stats."""
    if limiter is not None:
        probe = _throttled_probe(probe, limiter)

    ep_repo = EndpointRepo.from_mongo(mongo)
    endpoints = await ep_repo.list(tenant.tenant_id, program_id, limit=100_000)
    target_set = set(targets)
    forbidden = [
        e
        for e in endpoints
        if e.get("status_code") in _FORBIDDEN
        and not e.get("gone")
        and (not target_set or e.get("fingerprint") in target_set)
    ]
    if not forbidden:
        logger.info("403-bypass: no 401/403 endpoints to test")
        return {"skipped": True, "note": "no 401/403 endpoints", "endpoints": 0, "bypassed": 0}

    # host → resolved IPs, so scope can be evaluated without a live DNS round trip
    # (same source of truth as crawl's alive-gating).
    assets = await AssetRepo.from_mongo(mongo).list(tenant.tenant_id, program_id, limit=100_000)
    ips_by_host = {a["hostname"]: a.get("resolved_ips", []) for a in assets}

    forbidden = forbidden[:MAX_ENDPOINTS_PER_RUN]
    logger.info("403-bypass: testing {} forbidden endpoint(s)", len(forbidden))

    tested = 0
    total_bypasses = 0
    endpoints_bypassed = 0
    for ep in forbidden:
        url = ep["url"]
        host = urlsplit(url).hostname or ""
        decision = engine.evaluate(host, ips_by_host.get(host, []), scope)
        if not decision.permits(Action.HTTP_PROBE):
            logger.info("403-bypass: {} not permitted for active probing — skipping", host)
            continue

        tested += 1
        logger.info("403-bypass: probing {} (baseline {})", url, ep.get("status_code"))

        def _log_attempt(attempt) -> None:
            logger.debug("403-bypass: trying {} on {}", attempt.label, attempt.url)

        def _log_hit(record) -> None:
            logger.info(
                "403-bypass: BYPASS {} via {} → {} [{}]",
                record["url"],
                record["label"],
                record["status"],
                record["confidence"],
            )

        result = await run_bypass(url, probe=probe, on_attempt=_log_attempt, on_hit=_log_hit)
        bypasses = result.get("bypasses", [])
        await ep_repo.record_bypass(
            tenant.tenant_id, ep["fingerprint"], bypasses=bypasses, checked_at=datetime.now(UTC)
        )
        if bypasses:
            endpoints_bypassed += 1
            total_bypasses += len(bypasses)
        else:
            logger.info("403-bypass: no bypass found for {}", url)

    logger.info(
        "403-bypass: done — {} endpoint(s) tested, {} bypassable, {} technique(s)",
        tested,
        endpoints_bypassed,
        total_bypasses,
    )
    return {
        "endpoints": tested,
        "bypassed": endpoints_bypassed,
        "techniques": total_bypasses,
    }


async def run_bypass_scan(
    *,
    mongo: Any,
    engine: ScopeEngine,
    tenant: TenantContext,
    program_id: str,
    scan_id: str | None = None,
    targets: tuple[str, ...] = (),
    limiter: PolitenessLimiter | None = None,
    timeout: float = 10.0,
    probe=default_probe,
) -> dict:
    """ScanRun lifecycle wrapper so a bypass run shows in Activity with live logs.

    Enforces the §9b authorization gate up front (it makes active requests), then runs
    the engine inside a bound logging context with an updated-at heartbeat, mirroring
    :func:`pipelines.dispatch.run_pipeline`."""
    program = await ProgramRepo.from_mongo(mongo).get(tenant.tenant_id, program_id)
    if not program:
        raise AuthorizationRequired(f"no program {program_id} for tenant {tenant.tenant_id}")
    auth = await AuthorizationRepo.from_mongo(mongo).get(tenant.tenant_id, program_id)
    if not _auth_current(auth):
        raise AuthorizationRequired(f"no current authorization for program {program_id}")

    scope = build_program_scope(program, auth)
    audit = ScanRunRepo.from_mongo(mongo)
    heartbeat = 45
    run = ScanRun(
        tenant_id=tenant.tenant_id,
        scan_id=scan_id or uuid.uuid4().hex,
        program_id=program_id,
        pipeline="bypass_403",
        status=ScanStatus.RUNNING,
        started_at=datetime.now(UTC),
        targets=list(targets),
    )
    with bind_context(
        tenant_id=tenant.tenant_id,
        scan_id=run.scan_id,
        program_id=program_id,
        pipeline="bypass_403",
    ):
        await audit.save(run)
        logger.info("403-bypass started")
        task = asyncio.ensure_future(
            run_bypass_403(
                mongo=mongo,
                engine=engine,
                scope=scope,
                tenant=tenant,
                program_id=program_id,
                targets=targets,
                limiter=limiter,
                probe=probe,
            )
        )
        try:
            while True:
                done, _ = await asyncio.wait({task}, timeout=heartbeat)
                if task in done:
                    break
                run.updated_at = datetime.now(UTC)
                await audit.save(run)
            result = task.result()
        except Exception as exc:
            task.cancel()
            run.status = ScanStatus.FAILED
            run.finished_at = datetime.now(UTC)
            run.error = f"{type(exc).__name__}: {exc}"
            await audit.save(run)
            logger.error("403-bypass failed: {}", exc)
            raise
        run.finished_at = datetime.now(UTC)
        if result.get("skipped"):
            run.status = ScanStatus.SKIPPED
            run.note = result.get("note")
        else:
            run.status = ScanStatus.SUCCESS
            run.stats = {k: v for k, v in result.items() if isinstance(v, int)}
        await audit.save(run)
        return result
