"""Program (domain) CRUD, plus verification, authorization, scan trigger, and reads."""

from __future__ import annotations

import secrets
import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status

from api.deps import (
    Principal,
    clean_doc,
    get_domain_verifier,
    get_mongo_dep,
    get_principal,
    require_owner,
    require_program,
    require_verified_email,
    require_write_license,
)
from api.schemas import (
    AuthorizationCreate,
    ProgramCreate,
    VerifyCheckResponse,
    VerifyRequestResponse,
)
from core.alert_policy import (
    DEFAULT_ALERT_POLICY,
    effective_alert_policy,
    sanitize_alert_policy,
)
from core.config import get_settings
from core.liveness import (
    annotate_gone,
    const_phase,
    endpoint_phase,
    finding_phase,
    phase_reference_starts,
)
from core.models import (
    Authorization,
    IpScopeEntry,
    Program,
    ScanRun,
    ScanStage,
    ScanStatus,
    VerificationMethod,
)
from core.plans import max_domains
from core.scope import HTTP_LAYER_ACTIONS, PENDING, IpClass
from core.severity import Severity
from core.verification import dns_instructions, http_instructions
from db.assets import AssetRepo
from db.audit import ScanRunRepo
from db.authorizations import AuthorizationRepo
from db.cves import CveMatchRepo
from db.deltas import DeltaRepo
from db.domain_intel import DomainIntelRepo
from db.endpoints import EndpointRepo
from db.findings import FindingRepo
from db.jsfiles import JsFileRepo
from db.leaks import LeakRepo
from db.ports import PortRepo
from db.programs import (
    ProgramRepo,
    delete_program_and_data,
    program_within_plan,
    tenant_can_add_domain,
    tenant_plan,
)
from db.schedule import ScheduleRepo
from db.secrets import SecretRepo
from db.tenants import TenantRepo
from taskqueue.cadence import (
    effective_cadence,
    next_due,
    sanitize_overrides,
)
from taskqueue.timeouts import effective_timeouts, sanitize_timeout_overrides

router = APIRouter(prefix="/programs", tags=["programs"])


# -- CRUD --------------------------------------------------------------------
@router.get("")
async def list_programs(
    principal: Principal = Depends(get_principal), mongo: Any = Depends(get_mongo_dep)
) -> list[dict]:
    return [clean_doc(d) for d in await ProgramRepo.from_mongo(mongo).list(principal.tenant_id)]


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_program(
    body: ProgramCreate,
    principal: Principal = Depends(require_verified_email),
    mongo: Any = Depends(get_mongo_dep),
    _lic: None = Depends(require_write_license),
) -> dict:
    if not await tenant_can_add_domain(mongo, principal.tenant_id):
        cap = max_domains(await tenant_plan(mongo, principal.tenant_id))
        raise HTTPException(
            status.HTTP_402_PAYMENT_REQUIRED,
            f"your plan allows {cap} domain(s) — upgrade to add another",
        )
    program = Program(
        tenant_id=principal.tenant_id,
        program_id="prog_" + uuid.uuid4().hex[:12],
        apex_domain=body.apex_domain.lower().rstrip("."),
        excluded_hosts=body.excluded_hosts,
        excluded_cidrs=body.excluded_cidrs,
    )
    await ProgramRepo.from_mongo(mongo).save(program)
    return clean_doc(program.model_dump(mode="json"))


@router.get("/{program_id}")
async def get_program(program: dict = Depends(require_program)) -> dict:
    return clean_doc(program)


@router.delete("/{program_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_program(
    program: dict = Depends(require_program),
    _: Principal = Depends(require_owner),
    mongo: Any = Depends(get_mongo_dep),
) -> None:
    """Permanently remove a program and all of its discovered data (assets,
    endpoints, findings, scan history, …). To merely pause it without losing
    history, use the monitoring toggle instead."""
    await delete_program_and_data(mongo, program["tenant_id"], program["program_id"])


@router.post("/{program_id}/monitoring", tags=["programs"])
async def set_monitoring(
    enabled: bool = Query(...),
    program: dict = Depends(require_program),
    mongo: Any = Depends(get_mongo_dep),
) -> dict:
    """Enable/disable continuous monitoring for a program. Disabled → the scheduler
    skips it (no subdomain/asset discovery, crawl, or scans) but keeps existing data."""
    await ProgramRepo.from_mongo(mongo).set_enabled(
        program["tenant_id"], program["program_id"], enabled
    )
    return {"program_id": program["program_id"], "enabled": enabled}


@router.post("/{program_id}/assets/{fingerprint}/monitoring", tags=["programs"])
async def set_asset_monitoring(
    fingerprint: str,
    enabled: bool = Query(...),
    program: dict = Depends(require_program),
    principal: Principal = Depends(get_principal),
    mongo: Any = Depends(get_mongo_dep),
) -> dict:
    """Mute/unmute a single discovered asset. Unmonitored assets are skipped by
    crawl, content-discovery, and port-scan on subsequent runs."""
    ok = await AssetRepo.from_mongo(mongo).set_monitored(principal.tenant_id, fingerprint, enabled)
    if not ok:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "asset not found")
    return {"fingerprint": fingerprint, "monitored": enabled}


# -- schedule (cadence + last/next scan) -------------------------------------
def _iso(value: Any) -> str | None:
    return value.isoformat() if hasattr(value, "isoformat") else value


async def _schedule_view(mongo: Any, program: dict) -> dict:
    """Per-phase cadence with each phase's last-run + next-due, plus the last full
    run's start/finish. Powers the domains screen's 'last/next scan' breakdown."""
    tid, pid = program["tenant_id"], program["program_id"]
    prog_over = sanitize_overrides(program.get("cadence_overrides"))
    tenant = await TenantRepo.from_mongo(mongo).get(tid)
    tenant_over = sanitize_overrides((tenant or {}).get("cadence_overrides"))
    eff = effective_cadence(prog_over, tenant_over)

    schedule = ScheduleRepo.from_mongo(mongo)
    phases = []
    for pipeline, interval in eff.items():
        last = await schedule.last_run(tid, pid, pipeline)
        source = (
            "program"
            if pipeline in prog_over
            else "tenant"
            if pipeline in tenant_over
            else "default"
        )
        phases.append(
            {
                "pipeline": pipeline,
                "interval_seconds": interval,
                "last_run_at": _iso(last),
                "next_due_at": _iso(next_due(last, interval)),
                "source": source,
            }
        )
    phases.sort(key=lambda p: p["interval_seconds"])

    last_full = await ScanRunRepo.from_mongo(mongo).latest_full(tid, pid)
    return {
        "program_id": pid,
        "initial_scan_completed_at": _iso(program.get("initial_scan_completed_at")),
        "last_full_run": (
            {
                "scan_id": last_full.get("scan_id"),
                "status": last_full.get("status"),
                "started_at": _iso(last_full.get("started_at")),
                "finished_at": _iso(last_full.get("finished_at")),
            }
            if last_full
            else None
        ),
        "phases": phases,
    }


@router.get("/{program_id}/schedule", tags=["programs"])
async def get_schedule(
    program: dict = Depends(require_program), mongo: Any = Depends(get_mongo_dep)
) -> dict:
    return await _schedule_view(mongo, program)


@router.post("/{program_id}/schedule", tags=["programs"])
async def set_schedule(
    body: dict,
    program: dict = Depends(require_program),
    mongo: Any = Depends(get_mongo_dep),
) -> dict:
    """Set this program's per-pipeline cadence overrides (seconds). Unknown pipelines
    and sub-floor intervals are dropped/clamped server-side (politeness)."""
    overrides = sanitize_overrides(body.get("overrides") if isinstance(body, dict) else None)
    await ProgramRepo.from_mongo(mongo).set_cadence_overrides(
        program["tenant_id"], program["program_id"], overrides
    )
    program = {**program, "cadence_overrides": overrides}
    return await _schedule_view(mongo, program)


# -- attack-surface change analytics -----------------------------------------
@router.get("/{program_id}/attack-surface", tags=["data"])
async def attack_surface(
    program: dict = Depends(require_program),
    principal: Principal = Depends(get_principal),
    mongo: Any = Depends(get_mongo_dep),
) -> dict:
    """How the program's attack surface is changing over time — current active
    counts, what opened/closed since the last scan, a surface-size trend series,
    and a recent change log. Derived from state-aware first_seen/last_seen."""
    from core.attack_surface import _aware, compute_attack_surface

    tid, pid = principal.tenant_id, program["program_id"]
    items_by_type = {
        "assets": await AssetRepo.from_mongo(mongo).list(tid, pid, limit=100_000),
        "endpoints": await EndpointRepo.from_mongo(mongo).list(tid, pid, limit=100_000),
        "ports": await PortRepo.from_mongo(mongo).list(tid, pid, limit=100_000),
        "findings": await FindingRepo.from_mongo(mongo).list(tid, pid, limit=100_000),
        "secrets": await SecretRepo.from_mongo(mongo).list(tid, pid, limit=100_000),
        "leaks": await LeakRepo.from_mongo(mongo).list(tid, pid, limit=100_000),
    }
    # scan points = COMPLETED full runs (the natural "surface snapshot" moments).
    # reference = the latest COMPLETED full run's START — an item not re-observed
    # since then is resolved. Crucially we ignore an in-progress run: otherwise, mid
    # scan, everything not yet re-touched would look "resolved" and the tiles would
    # collapse to near-zero until the scan finished (the "0 then populates" bug).
    runs = await ScanRunRepo.from_mongo(mongo).list(tid, pid, limit=1000)
    completed_full = [
        r for r in runs if r.get("pipeline") == "full" and r.get("finished_at") is not None
    ]
    scan_points = [p for p in (_aware(r.get("finished_at")) for r in completed_full) if p]
    starts = [p for p in (_aware(r.get("started_at")) for r in completed_full) if p]
    reference = max(starts, default=None)
    return compute_attack_surface(
        items_by_type=items_by_type, scan_points=scan_points, reference=reference
    )


# -- per-phase time limits ---------------------------------------------------
async def _timeouts_view(mongo: Any, program: dict) -> dict:
    tid = program["tenant_id"]
    prog_over = sanitize_timeout_overrides(program.get("timeout_overrides"))
    tenant = await TenantRepo.from_mongo(mongo).get(tid)
    tenant_over = sanitize_timeout_overrides((tenant or {}).get("timeout_overrides"))
    eff = effective_timeouts(prog_over, tenant_over)
    stages = [
        {
            "stage": stage,
            "timeout_seconds": secs,
            "source": (
                "program" if stage in prog_over else "tenant" if stage in tenant_over else "default"
            ),
        }
        for stage, secs in eff.items()
    ]
    return {"program_id": program["program_id"], "stages": stages}


@router.get("/{program_id}/timeouts", tags=["programs"])
async def get_timeouts(
    program: dict = Depends(require_program), mongo: Any = Depends(get_mongo_dep)
) -> dict:
    return await _timeouts_view(mongo, program)


@router.post("/{program_id}/timeouts", tags=["programs"])
async def set_timeouts(
    body: dict,
    program: dict = Depends(require_program),
    mongo: Any = Depends(get_mongo_dep),
) -> dict:
    """Set this program's per-stage max-runtime overrides (seconds). Out-of-range
    values are clamped to [MIN, MAX] server-side."""
    overrides = sanitize_timeout_overrides(
        body.get("overrides") if isinstance(body, dict) else None
    )
    await ProgramRepo.from_mongo(mongo).set_timeout_overrides(
        program["tenant_id"], program["program_id"], overrides
    )
    return await _timeouts_view(mongo, {**program, "timeout_overrides": overrides})


async def _alert_policy_view(mongo: Any, program: dict) -> dict:
    """This program's own overrides + the effective (defaults←tenant←program) policy
    that notify actually enforces, plus the field catalog for the settings UI."""
    tenant = await TenantRepo.from_mongo(mongo).get(program["tenant_id"])
    prog_ov = program.get("alert_policy")
    tenant_def = (tenant or {}).get("alert_policy")
    return {
        "alert_policy": sanitize_alert_policy(prog_ov),
        "effective": effective_alert_policy(prog_ov, tenant_def),
        "defaults": DEFAULT_ALERT_POLICY,
        "tenant_defaults": sanitize_alert_policy(tenant_def),
        "severities": [s.value for s in Severity],
    }


@router.get("/{program_id}/alert-policy", tags=["programs"])
async def get_alert_policy(
    program: dict = Depends(require_program), mongo: Any = Depends(get_mongo_dep)
) -> dict:
    return await _alert_policy_view(mongo, program)


@router.post("/{program_id}/alert-policy", tags=["programs"])
async def set_alert_policy(
    body: dict,
    program: dict = Depends(require_program),
    mongo: Any = Depends(get_mongo_dep),
) -> dict:
    """Set this program's alert-policy overrides. Unknown keys / bad values are dropped
    and the port filter is normalised server-side."""
    policy = sanitize_alert_policy(body.get("policy") if isinstance(body, dict) else None)
    await ProgramRepo.from_mongo(mongo).set_alert_policy(
        program["tenant_id"], program["program_id"], policy
    )
    return await _alert_policy_view(mongo, {**program, "alert_policy": policy})


# -- domain verification -----------------------------------------------------
@router.post("/{program_id}/verify/request", response_model=VerifyRequestResponse)
async def request_verification(
    method: VerificationMethod = Query(default=VerificationMethod.DNS_TXT),
    program: dict = Depends(require_program),
    mongo: Any = Depends(get_mongo_dep),
) -> VerifyRequestResponse:
    token = "exactsurface-verify=" + secrets.token_hex(16)
    await ProgramRepo.from_mongo(mongo).set_verification(
        program["tenant_id"], program["program_id"], method.value, token
    )
    apex = program["apex_domain"]
    instr = (
        dns_instructions(apex, token)
        if method == VerificationMethod.DNS_TXT
        else http_instructions(apex, token)
    )
    return VerifyRequestResponse(method=method, token=token, instructions=instr)


@router.post("/{program_id}/verify/check", response_model=VerifyCheckResponse)
async def check_verification(
    program: dict = Depends(require_program),
    mongo: Any = Depends(get_mongo_dep),
    verifier=Depends(get_domain_verifier),
) -> VerifyCheckResponse:
    token = program.get("verification_token")
    method = program.get("verification_method")
    if not token or not method:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "request a challenge first")
    ok = await verifier.verify(program["apex_domain"], method, token)
    if ok:
        await ProgramRepo.from_mongo(mongo).set_verified(
            program["tenant_id"], program["program_id"], True
        )
    return VerifyCheckResponse(verified=ok, detail="verified" if ok else "challenge not found")


# -- authorization -----------------------------------------------------------
@router.post("/{program_id}/authorization", status_code=status.HTTP_201_CREATED)
async def create_authorization(
    body: AuthorizationCreate,
    program: dict = Depends(require_program),
    principal: Principal = Depends(require_owner),
    mongo: Any = Depends(get_mongo_dep),
) -> dict:
    if not program.get("verified"):
        raise HTTPException(
            status.HTTP_409_CONFLICT, "domain must be verified before authorization"
        )
    # §9b step 3: the client only REQUESTS CIDRs. They are recorded as pending,
    # HTTP-layer-only, and are promoted to DEDICATED solely by the worker after
    # asnmap confirms them against the verified apex's announced ASN ranges — the
    # API host has no asnmap (§3.8 keeps it separate), and self-attestation must
    # never grant aggressive scanning of infrastructure the customer may not own.
    requested = [
        IpScopeEntry(
            cidr=cidr,
            ip_class=IpClass.PUBLIC.value,
            action_set=sorted(a.value for a in HTTP_LAYER_ACTIONS),
            confirmed_via=PENDING,
        )
        for cidr in body.ip_scope
    ]
    auth = Authorization(
        tenant_id=principal.tenant_id,
        program_id=program["program_id"],
        authorized_by=principal.user_id or "apikey",
        apex_verified=True,
        verification_method=program.get("verification_method"),
        ip_scope=requested,
        tos_version=body.tos_version,
    )
    await AuthorizationRepo.from_mongo(mongo).save(auth)
    return clean_doc(auth.model_dump(mode="json"))


@router.get("/{program_id}/authorization")
async def get_authorization(
    program: dict = Depends(require_program),
    principal: Principal = Depends(get_principal),
    mongo: Any = Depends(get_mongo_dep),
) -> dict:
    doc = await AuthorizationRepo.from_mongo(mongo).get(principal.tenant_id, program["program_id"])
    if not doc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no authorization record")
    return clean_doc(doc)


# -- scan config -------------------------------------------------------------
@router.post("/{program_id}/scan-config", tags=["programs"])
async def set_scan_config(
    scan_shared_infra: bool = Query(...),
    program: dict = Depends(require_program),
    principal: Principal = Depends(get_principal),
    mongo: Any = Depends(get_mongo_dep),
) -> dict:
    """Toggle the §9b opt-in: when on, the customer attests they own the cloud
    infra their domain runs on, so ports/content/active scans run on cloud/public
    IPs too (third-party CDNs and internal ranges stay locked by the scope engine)."""
    await ProgramRepo.from_mongo(mongo).set_scan_shared_infra(
        principal.tenant_id, program["program_id"], scan_shared_infra
    )
    return {"program_id": program["program_id"], "scan_shared_infra": scan_shared_infra}


@router.post("/{program_id}/modules", tags=["programs"])
async def set_modules(
    enabled: list[str],
    program: dict = Depends(require_program),
    principal: Principal = Depends(get_principal),
    mongo: Any = Depends(get_mongo_dep),
) -> dict:
    """Opt IN to modules that are off by default (tls, dork, uncover, …).

    Kept for backwards compatibility with the program page's module switches. The
    richer control — including turning default-on modules OFF — is
    ``PUT /{program_id}/modules``.
    """
    from core.modules import OPT_IN

    modules = sorted({m for m in enabled if m in OPT_IN})
    await ProgramRepo.from_mongo(mongo).set_enabled_modules(
        principal.tenant_id, program["program_id"], modules
    )
    return {"program_id": program["program_id"], "enabled_modules": modules}


@router.get("/{program_id}/modules", tags=["programs"])
async def get_modules(program: dict = Depends(require_program)) -> dict:
    """Every module with its current state, dependencies, and — for anything that will
    not run — the reason. This is what the settings screen renders, including the
    warning that turning one module off also stops the modules that depend on it."""
    from core.modules import catalogue

    return {
        "program_id": program["program_id"],
        "modules": catalogue(
            enabled_modules=program.get("enabled_modules"),
            disabled_modules=program.get("disabled_modules"),
        ),
    }


@router.put("/{program_id}/modules", tags=["programs"])
async def update_modules(
    body: dict,
    program: dict = Depends(require_program),
    principal: Principal = Depends(get_principal),
    mongo: Any = Depends(get_mongo_dep),
) -> dict:
    """Set which modules run for this program.

    ``{"enabled": [...], "disabled": [...]}``. Essential modules (subdomain discovery,
    live-host probing) are silently dropped from the disable list — everything reads
    their output, so switching them off would leave a scanner that finds nothing.
    """
    from core.modules import OPT_IN, catalogue, sanitize_disabled

    enabled = sorted({str(m) for m in (body.get("enabled") or []) if str(m) in OPT_IN})
    disabled = sanitize_disabled(body.get("disabled"))

    repo = ProgramRepo.from_mongo(mongo)
    tid, pid = principal.tenant_id, program["program_id"]
    await repo.set_enabled_modules(tid, pid, enabled)
    await repo.set_disabled_modules(tid, pid, disabled)
    return {
        "program_id": pid,
        "enabled_modules": enabled,
        "disabled_modules": disabled,
        "modules": catalogue(enabled_modules=enabled, disabled_modules=disabled),
    }


# -- scan trigger (auth-gated) ----------------------------------------------
@router.post("/{program_id}/scan", status_code=status.HTTP_202_ACCEPTED)
async def trigger_scan(
    program: dict = Depends(require_program),
    principal: Principal = Depends(get_principal),
    mongo: Any = Depends(get_mongo_dep),
    _lic: None = Depends(require_write_license),
) -> dict:
    if not program.get("verified"):
        raise HTTPException(status.HTTP_409_CONFLICT, "verify the domain first")
    # §13: plan limits are checked before a scan consumes resources. A program
    # outside the allowance (e.g. after a downgrade) is refused explicitly rather
    # than silently skipped, so the user sees why.
    if not await program_within_plan(mongo, principal.tenant_id, program["program_id"]):
        cap = max_domains(await tenant_plan(mongo, principal.tenant_id))
        raise HTTPException(
            status.HTTP_402_PAYMENT_REQUIRED,
            f"your plan covers {cap} domain(s); this one is outside that allowance — "
            "upgrade or remove another domain to scan it",
        )
    auth = await AuthorizationRepo.from_mongo(mongo).get(principal.tenant_id, program["program_id"])
    if not (auth and auth.get("apex_verified") and not auth.get("revoked")):
        raise HTTPException(
            status.HTTP_409_CONFLICT, "a current authorization record is required before scanning"
        )

    from core.logging import logger
    from pipelines.orchestrate import FULL_STAGE_NAMES

    tid, pid = principal.tenant_id, program["program_id"]
    audit = ScanRunRepo.from_mongo(mongo)
    settings = get_settings()

    # Refuse a duplicate scan while one is already in flight (backend-enforced —
    # not just a disabled button; a direct API call is blocked too). A stale run
    # (worker died) does not count as active, so scanning is never blocked forever.
    active = await audit.find_active_full(tid, pid, stale_seconds=settings.scan_run_stale_seconds)
    if active is not None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "a scan is already running for this program; wait for it to finish",
        )

    # Record a QUEUED run up front so the button click shows immediately and the
    # worker reuses this row (no duplicate). Pre-render the stepper as all-queued.
    scan_id = uuid.uuid4().hex
    await audit.save(
        ScanRun(
            tenant_id=tid,
            program_id=pid,
            scan_id=scan_id,
            pipeline="full",
            status=ScanStatus.QUEUED,
            stages=[ScanStage(name=name) for name in FULL_STAGE_NAMES],
        )
    )

    # Enqueue so a worker picks it up immediately. If Redis is unreachable, the
    # scheduler still runs it on its normal cadence (the QUEUED row is then reaped
    # if never claimed).
    enqueued = False
    try:
        from taskqueue.arq_client import create_pool

        pool = await create_pool()
        try:
            # force=True: an explicit user scan runs even if monitoring is paused.
            await pool.enqueue_job("run_program_task", tid, pid, scan_id=scan_id, force=True)
            enqueued = True
        finally:
            await pool.aclose()
    except Exception as exc:  # noqa: BLE001 - fall back to scheduler cadence
        logger.warning("scan enqueue failed (scheduler will still run it): {}", exc)

    if not enqueued:
        # Don't leave a phantom QUEUED "full" row blocking future scans: the
        # scheduler runs individual pipelines on cadence, not this full row.
        await audit.save(
            ScanRun(
                tenant_id=tid,
                program_id=pid,
                scan_id=scan_id,
                pipeline="full",
                status=ScanStatus.FAILED,
                note="could not enqueue now; the scheduler will run pipelines on cadence",
            )
        )

    return {
        "status": "queued" if enqueued else "scheduled",
        "program_id": pid,
        "scan_id": scan_id,
        "detail": (
            "A worker is running the scan now; findings appear as they are discovered."
            if enqueued
            else "Couldn't start immediately; the scheduler will run it on its next cycle."
        ),
    }


@router.post("/{program_id}/scan-runs/{scan_id}/cancel", status_code=status.HTTP_202_ACCEPTED)
async def cancel_scan_run(
    scan_id: str,
    program: dict = Depends(require_program),
    principal: Principal = Depends(get_principal),
    mongo: Any = Depends(get_mongo_dep),
) -> dict:
    """Ask a running scan to stop.

    Cooperative, not a kill: this records the request and returns immediately. The
    worker notices it within one heartbeat (~45s at worst, usually sooner), kills the
    tool it is running, marks the remaining stages cancelled, and finishes the run in a
    clean ``cancelled`` state. Everything discovered up to that point is kept — every
    write is an idempotent upsert — and a new scan can be started straight after.

    Deliberately no licence gate: stopping work must always be possible, even read-only.
    """
    run = await ScanRunRepo.from_mongo(mongo).get(principal.tenant_id, scan_id)
    if not run or run.get("program_id") != program["program_id"]:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan run not found")
    if run.get("status") not in (ScanStatus.QUEUED.value, ScanStatus.RUNNING.value):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"this scan is already {run.get('status')} — nothing to stop",
        )

    await ScanRunRepo.from_mongo(mongo).request_cancel(
        principal.tenant_id, scan_id, actor=principal.user_id
    )
    return {
        "status": "stopping",
        "scan_id": scan_id,
        "detail": (
            "Stop requested. The current step is being wound down; findings already "
            "discovered are kept. You can start a new scan once it finishes."
        ),
    }


# -- 403-bypass (on-demand, user-triggered; NOT a pipeline phase) ------------
@router.post("/{program_id}/bypass-403", status_code=status.HTTP_202_ACCEPTED)
async def trigger_bypass_403(
    program: dict = Depends(require_program),
    principal: Principal = Depends(get_principal),
    mongo: Any = Depends(get_mongo_dep),
    _lic: None = Depends(require_write_license),
) -> dict:
    """Run the 403/401-bypass module across this program's forbidden endpoints.

    On-demand only (the Endpoints-tab button) — never scheduled. Detection-only: it
    sends the same benign probes an attacker would, records any endpoint whose 403 can
    be bypassed, and changes nothing on the target. Gated exactly like a scan (verified
    + current authorization) because it makes active requests; the programs router
    already requires ``programs.manage`` for this write.
    """
    from core.logging import logger

    if not program.get("verified"):
        raise HTTPException(status.HTTP_409_CONFLICT, "verify the domain first")
    auth = await AuthorizationRepo.from_mongo(mongo).get(principal.tenant_id, program["program_id"])
    if not (auth and auth.get("apex_verified") and not auth.get("revoked")):
        raise HTTPException(
            status.HTTP_409_CONFLICT, "a current authorization record is required first"
        )

    tid, pid = principal.tenant_id, program["program_id"]
    audit = ScanRunRepo.from_mongo(mongo)

    # Refuse a duplicate bypass run while one is already in flight for this program.
    if await audit.active_phase_run(tid, pid, "bypass_403", fresh_seconds=180):
        raise HTTPException(
            status.HTTP_409_CONFLICT, "a 403-bypass run is already in progress for this program"
        )

    scan_id = uuid.uuid4().hex
    await audit.save(
        ScanRun(
            tenant_id=tid,
            program_id=pid,
            scan_id=scan_id,
            pipeline="bypass_403",
            status=ScanStatus.QUEUED,
        )
    )

    enqueued = False
    try:
        from taskqueue.arq_client import create_pool

        pool = await create_pool()
        try:
            await pool.enqueue_job("run_bypass_task", tid, pid, scan_id=scan_id)
            enqueued = True
        finally:
            await pool.aclose()
    except Exception as exc:  # noqa: BLE001
        logger.warning("403-bypass enqueue failed: {}", exc)

    if not enqueued:
        await audit.save(
            ScanRun(
                tenant_id=tid,
                program_id=pid,
                scan_id=scan_id,
                pipeline="bypass_403",
                status=ScanStatus.FAILED,
                note="couldn't start the 403-bypass run — is the worker running?",
            )
        )
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "couldn't start the 403-bypass run — no worker available right now",
        )

    return {
        "status": "queued",
        "program_id": pid,
        "scan_id": scan_id,
        "detail": "Running 403-bypass — watch the Activity tab; results attach to endpoints.",
    }


@router.post("/{program_id}/run-module", status_code=status.HTTP_202_ACCEPTED)
async def run_single_module(
    body: dict,
    program: dict = Depends(require_program),
    principal: Principal = Depends(get_principal),
    mongo: Any = Depends(get_mongo_dep),
    _lic: None = Depends(require_write_license),
) -> dict:
    """Run ONE module on demand — the developer console.

    The product normally runs modules two ways: the whole ordered pipeline, or the
    scheduler's per-phase cadence. Neither is usable when you are developing a module
    and want to see what it does *right now*, so this exposes the third way the
    dispatcher already supports: one named module, this program, immediately.

    It is the same ``run_pipeline`` path the scheduler uses — not a parallel
    implementation — so what you see here is exactly what production does, including
    the scope checks, the authorization gate, the politeness limiter and the module
    on/off resolution. A module disabled in settings will report itself skipped here
    too; that is the honest answer, not a bug to work around.

    Requires the same verified + authorized program as a scan, because these modules
    make real requests to real hosts.
    """
    from core import modules as module_registry
    from core.logging import logger

    name = str(body.get("module") or "").strip()
    if name not in module_registry.BY_NAME:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"unknown module {name!r}; expected one of: "
            + ", ".join(module_registry.MODULE_NAMES),
        )
    if not program.get("verified"):
        raise HTTPException(status.HTTP_409_CONFLICT, "verify the domain first")
    auth = await AuthorizationRepo.from_mongo(mongo).get(principal.tenant_id, program["program_id"])
    if not (auth and auth.get("apex_verified") and not auth.get("revoked")):
        raise HTTPException(
            status.HTTP_409_CONFLICT, "a current authorization record is required first"
        )

    tid, pid = principal.tenant_id, program["program_id"]
    audit = ScanRunRepo.from_mongo(mongo)
    if await audit.active_phase_run(tid, pid, name, fresh_seconds=180):
        raise HTTPException(
            status.HTTP_409_CONFLICT, f"{name} is already running for this program"
        )

    try:
        from taskqueue.arq_client import create_pool

        pool = await create_pool()
        try:
            await pool.enqueue_job("run_pipeline_task", tid, pid, name)
        finally:
            await pool.aclose()
    except Exception as exc:  # noqa: BLE001
        logger.warning("single-module enqueue failed for {}: {}", name, exc)
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            f"couldn't start {name} — no worker available right now",
        ) from exc

    logger.info("developer console: {} queued for {}", name, pid)
    return {
        "status": "queued",
        "module": name,
        "label": module_registry.BY_NAME[name].label,
        "program_id": pid,
        "detail": f"Running {name} on its own — watch the log stream below.",
    }


# -- reads -------------------------------------------------------------------
async def _phase_refs(mongo: Any, tenant_id: str, program_id: str) -> dict:
    """Per-phase full-coverage-run reference starts for gone-detection (core.liveness)."""
    runs = await ScanRunRepo.from_mongo(mongo).list(tenant_id, program_id, limit=500)
    return phase_reference_starts(runs)


#: Default page size for a data reader. Endpoints override it: a real surface produces
#: far more than 1000 (crawl + archives + content discovery + JS mining), and a short
#: page silently hides whole SOURCES — the feroxbuster/JS endpoints simply fell off the
#: end, so their filter chips and the 403-bypass button never appeared.
_READ_LIMIT = 1000
_ENDPOINT_READ_LIMIT = 10_000


def _reader(repo_cls, *, phase_of=None, limit: int = _READ_LIMIT):
    async def read(
        program: dict = Depends(require_program),
        principal: Principal = Depends(get_principal),
        mongo: Any = Depends(get_mongo_dep),
    ) -> list[dict]:
        docs = await repo_cls.from_mongo(mongo).list(
            principal.tenant_id, program["program_id"], limit=limit
        )
        if phase_of is not None:
            refs = await _phase_refs(mongo, principal.tenant_id, program["program_id"])
            annotate_gone(docs, refs, phase_of)  # tag `gone` before dates serialise
        return [clean_doc(d) for d in docs]

    return read


router.add_api_route(
    "/{program_id}/assets",
    _reader(AssetRepo, phase_of=const_phase("ingest")),
    methods=["GET"],
    tags=["data"],
)
router.add_api_route(
    "/{program_id}/endpoints",
    _reader(EndpointRepo, phase_of=endpoint_phase, limit=_ENDPOINT_READ_LIMIT),
    methods=["GET"],
    tags=["data"],
)
router.add_api_route("/{program_id}/secrets", _reader(SecretRepo), methods=["GET"], tags=["data"])
router.add_api_route(
    "/{program_id}/ports",
    _reader(PortRepo, phase_of=const_phase("port_scan")),
    methods=["GET"],
    tags=["data"],
)
router.add_api_route("/{program_id}/leaks", _reader(LeakRepo), methods=["GET"], tags=["data"])
router.add_api_route(
    "/{program_id}/cves",
    _reader(CveMatchRepo, phase_of=const_phase("cve_watch")),
    methods=["GET"],
    tags=["data"],
)
router.add_api_route("/{program_id}/deltas", _reader(DeltaRepo), methods=["GET"], tags=["data"])
router.add_api_route(
    "/{program_id}/scan-runs", _reader(ScanRunRepo), methods=["GET"], tags=["data"]
)
@router.get("/{program_id}/domain-intel", tags=["data"])
async def get_domain_intel(
    program: dict = Depends(require_program),
    principal: Principal = Depends(get_principal),
    mongo: Any = Depends(get_mongo_dep),
) -> dict:
    """Email posture + registration facts for this domain — the current state, as
    opposed to the Findings the same assessment raised."""
    doc = await DomainIntelRepo.from_mongo(mongo).get(
        principal.tenant_id, program["program_id"]
    )
    return clean_doc(doc) or {"email": {}, "registration": {}}


# Mined JavaScript bundles + everything extracted from them (the JS Mine view).
router.add_api_route("/{program_id}/js-files", _reader(JsFileRepo), methods=["GET"], tags=["data"])


@router.get("/{program_id}/scan-runs/{scan_id}/logs", tags=["data"])
async def scan_run_logs(
    scan_id: str,
    program: dict = Depends(require_program),
    principal: Principal = Depends(get_principal),
    mongo: Any = Depends(get_mongo_dep),
) -> dict:
    """Live log lines for one scan run (what each tool is doing), for the
    expandable activity panel. Tenant/program-scoped: the run must belong to the
    caller's program. Returns [] when no live bus is configured."""
    run = await ScanRunRepo.from_mongo(mongo).get(principal.tenant_id, scan_id)
    if not run or run.get("program_id") != program["program_id"]:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan run not found")

    from core.activity_bus import get_bus

    bus = get_bus()
    lines = await bus.get_logs(scan_id) if bus is not None and hasattr(bus, "get_logs") else []
    return {"scan_id": scan_id, "lines": lines}


@router.get("/{program_id}/findings", tags=["data"])
async def list_findings(
    severity: str | None = None,
    state: str | None = None,
    is_new: bool | None = None,
    program: dict = Depends(require_program),
    principal: Principal = Depends(get_principal),
    mongo: Any = Depends(get_mongo_dep),
) -> list[dict]:
    docs = await FindingRepo.from_mongo(mongo).list(
        principal.tenant_id, program["program_id"], is_new=is_new, limit=1000
    )
    # A finding is "gone" (resolved) only when a full-coverage re-run of its producing
    # module (nuclei→scan, tlsx→tls, dork, takeover) stopped reporting it.
    refs = await _phase_refs(mongo, principal.tenant_id, program["program_id"])
    annotate_gone(docs, refs, finding_phase)
    if severity:
        docs = [d for d in docs if d.get("severity") == severity]
    if state:
        docs = [d for d in docs if d.get("state") == state]
    return [clean_doc(d) for d in docs]


@router.get("/{program_id}/correlation", tags=["data"])
async def correlation(
    program: dict = Depends(require_program),
    principal: Principal = Depends(get_principal),
    mongo: Any = Depends(get_mongo_dep),
) -> dict:
    """Risk-ranked, correlated issues (module 27) computed on demand from every stored
    signal (assets/findings/secrets/leaks/CVEs/ports). The correlate stage discards its
    result, so the dashboard recomputes it here from the persisted data."""
    from core.tenant import TenantContext
    from pipelines.correlate import run_correlate

    return await run_correlate(
        mongo=mongo,
        tenant=TenantContext(principal.tenant_id),
        program_id=program["program_id"],
    )


@router.get("/{program_id}/attack-paths", tags=["data"])
async def attack_paths(
    program: dict = Depends(require_program),
    principal: Principal = Depends(get_principal),
    mongo: Any = Depends(get_mongo_dep),
) -> dict:
    """Findings on one host, told in attacker order — the narrative layer.

    Computed live from stored findings rather than persisted, so it can never go stale
    against the evidence it summarises. Every step carries the fingerprint of the
    finding it came from: the story is a reading of the data, and the reader can check
    it. A host whose findings span fewer than two attacker phases produces no path.
    """
    from dataclasses import asdict

    from modules.intelligence.narrative import build_paths

    rows = await FindingRepo.from_mongo(mongo).list(
        principal.tenant_id, program["program_id"], limit=100_000
    )
    paths = build_paths(rows)
    return {"count": len(paths), "paths": [asdict(p) for p in paths]}
