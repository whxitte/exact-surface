"""Full-pipeline orchestration: ingest → probe → scan for one program.

This is what a worker runs for a program. It (1) refuses to proceed without a
current authorization record (§9b/§9e), (2) builds the ``ProgramScope`` from the
program + authorization, (3) runs the three pipelines in order, and (4) records a
``ScanRun`` audit row with per-stage stats.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime
from typing import Any

from core.errors import AuthorizationRequired
from core.logging import bind_context, logger
from core.models import ScanRun, ScanStage, ScanStatus
from core.scope import ProgramScope, ScopeEngine, confirm_ip_scope, is_asn_confirmed
from core.tenant import TenantContext
from db.audit import ScanRunRepo
from db.authorizations import AuthorizationRepo
from db.programs import ProgramRepo, program_within_plan
from pipelines.cloud_buckets import run_cloud_buckets
from pipelines.content_discovery import run_content_discovery
from pipelines.correlate import run_correlate
from pipelines.crawl import run_crawl
from pipelines.cve_watch import run_cve_watch
from pipelines.dork import run_dork
from pipelines.github_osint import run_github_leak_scan
from pipelines.ingest import run_ingest
from pipelines.notify import run_notify
from pipelines.nuclei_watch import run_nuclei_watch
from pipelines.port_scan import run_port_scan
from pipelines.probe import run_probe
from pipelines.scan import run_scan
from pipelines.secrets import run_secret_scan
from pipelines.service_scan import run_service_scan
from pipelines.takeover import run_takeover
from pipelines.tls import run_tls_scan
from pipelines.uncover import run_uncover


def build_program_scope(program: dict, authorization: dict | None) -> ProgramScope:
    """Assemble the immutable scope object the engine evaluates against.

    Only ip_scope entries the **server** confirmed against real ASN data are
    honoured (§9b step 3). A ``dedicated`` class alone is not enough — an entry
    must also carry the ``asnmap:`` confirmation marker, which the API can never
    set from client input. An unconfirmed CIDR therefore grants HTTP-layer access
    only, no matter what the request body claimed.
    """
    dedicated: tuple[str, ...] = ()
    if authorization:
        dedicated = tuple(
            e["cidr"] for e in authorization.get("ip_scope", []) if is_asn_confirmed(e)
        )
    return ProgramScope(
        verified_apexes=(program["apex_domain"],),
        excluded_hosts=frozenset(program.get("excluded_hosts", [])),
        excluded_cidrs=tuple(program.get("excluded_cidrs", [])),
        authorized_dedicated_cidrs=dedicated,
        scan_shared_infra=bool(program.get("scan_shared_infra", False)),
    )


def _auth_is_current(auth: dict | None) -> bool:
    return bool(auth and auth.get("apex_verified") and not auth.get("revoked"))


#: How long asnmap gets to confirm the authorization's IP scope.
ASN_CONFIRM_TIMEOUT = 60.0


async def confirm_authorization_ip_scope(
    mongo: Any,
    program: dict,
    auth: dict,
    *,
    engine: ScopeEngine,
    asn_ranges=None,
) -> dict:
    """Confirm the authorization's requested CIDRs against real ASN data (§9b step 3).

    Runs on the **worker**, which is the only host with ``asnmap`` (§3.8 keeps the
    API slim). The verdict is written back into the authorization record so the
    confirmation is auditable (§5d), then the scope is built from it.

    Fails safe: if asnmap is missing, times out, or errors, nothing is confirmed —
    every CIDR stays HTTP-layer only. Losing ASN data must never *grant* access.
    """
    requested = [e.get("cidr") for e in auth.get("ip_scope", []) if e.get("cidr")]
    if not requested:
        return auth

    ranges: list[str] = []
    try:
        lookup = asn_ranges or _default_asn_ranges
        ranges = await lookup(program["apex_domain"], ASN_CONFIRM_TIMEOUT)
    except Exception as exc:  # noqa: BLE001 - no ASN data ⇒ confirm nothing
        logger.warning(
            "asnmap confirmation unavailable for {} ({}) — IP scope stays unconfirmed",
            program["apex_domain"],
            type(exc).__name__,
        )

    entries = confirm_ip_scope(requested, ranges, engine=engine)
    await AuthorizationRepo.from_mongo(mongo).set_ip_scope(
        auth["tenant_id"], auth["program_id"], entries
    )
    confirmed = [e["cidr"] for e in entries if is_asn_confirmed(e)]
    logger.info(
        "ip-scope confirmation for {}: {} requested → {} confirmed dedicated {}",
        program["apex_domain"],
        len(requested),
        len(confirmed),
        confirmed or "",
    )
    return {**auth, "ip_scope": entries}


async def _default_asn_ranges(apex: str, timeout: float) -> list[str]:
    from modules.osint.asn_mapper import map_domain

    return await map_domain(apex, timeout)


#: how often to re-save a running ScanRun so its ``updated_at`` reflects liveness.
STAGE_HEARTBEAT_SECONDS = 45


async def _run_stage_with_heartbeat(coro, *, budget: float, run, audit) -> dict:
    """Await a stage coroutine with a hard *budget*, re-saving *run* every
    ``STAGE_HEARTBEAT_SECONDS`` so ``updated_at`` reflects that work is ongoing — a
    single stage (nuclei) can run for an hour, and without a heartbeat the UI would
    label an actively-working scan "stalled". Raises ``TimeoutError`` past the budget,
    propagates the stage's own exception, and re-raises an outer ``CancelledError``."""
    task = asyncio.ensure_future(coro)
    elapsed = 0.0
    try:
        while True:
            remaining = budget - elapsed
            if remaining <= 0:
                task.cancel()
                raise TimeoutError
            wait = min(STAGE_HEARTBEAT_SECONDS, remaining)
            done, _ = await asyncio.wait({task}, timeout=wait)
            if task in done:
                return task.result()
            elapsed += wait
            run.updated_at = datetime.now(UTC)
            await audit.save(run)  # heartbeat
    except asyncio.CancelledError:
        task.cancel()
        raise


#: optional modules — off by default, toggled per program via ``enabled_modules``.
#: Each has a stage in the pipeline that renders as a (gray) SKIPPED node when the
#: module is disabled, and runs its tool when enabled.
OPTIONAL_MODULES: tuple[str, ...] = (
    "uncover",
    "tls",
    "service_scan",
    "dork",
    # cloud_buckets needs no API key, but it probes ~45 third-party endpoints per
    # run and its attribution is name-derived (a bucket matching your domain label
    # may not be yours) — so it is opt-in, like dork.
    "cloud_buckets",
    #: nuclei_watch needs an injected template lister (nuclei -tl contract unverified
    #: against the pinned binary) — opt-in until that is confirmed.
    "nuclei_watch",
)

#: canonical full-pipeline stage order — the complete outside-in attacker chain,
#: shared with the API so an enqueue-time QUEUED ScanRun pre-renders the same
#: stepper. Core stages self-skip when they have nothing to do; the OPTIONAL_MODULES
#: stages self-skip as "disabled" unless enabled for the program.
FULL_STAGE_NAMES: tuple[str, ...] = (
    "ingest",
    "uncover",  # optional — Shodan/Censys passive discovery
    "probe",
    "tls",  # optional
    "takeover",
    "crawl",
    "content_discovery",
    "port_scan",
    "service_scan",  # optional
    "scan",
    "secrets",
    "cve_watch",
    "github_osint",
    "cloud_buckets",  # optional — S3/GCS/Azure permutation
    "nuclei_watch",  # optional — new template → targeted re-scan
    "dork",  # optional
    "correlate",
    "notify",
)


async def run_full_pipeline(
    *,
    mongo: Any,
    engine: ScopeEngine,
    scope: ProgramScope,
    tenant: TenantContext,
    program_id: str,
    apex: str,
    timeout: float,
    scan_id: str | None = None,
    enabled_modules: tuple[str, ...] = (),
    timeouts: dict[str, int] | None = None,
    **injected: Any,
) -> dict:
    """Run the full outside-in pipeline: discover → probe → (tls) → crawl → content
    → ports → (services) → scan → secrets → CVE → GitHub OSINT → (dork) → correlate
    → notify.

    ``scan_id`` reuses a pre-created (QUEUED) ScanRun so the API's enqueue-time row
    becomes this run rather than a second row; omitted, a fresh id is generated.
    ``enabled_modules`` turns on the OPTIONAL_MODULES stages (else they render as a
    disabled/gray node). ``injected`` forwards test doubles per stage."""
    scan_id = scan_id or uuid.uuid4().hex
    audit = ScanRunRepo.from_mongo(mongo)

    # per-stage max runtime (built-ins ← tenant ← program); the tool budget for
    # tool stages + the wait_for ceiling for every stage. See taskqueue.timeouts.
    from taskqueue.timeouts import DEFAULT_TIMEOUTS_SECONDS, STAGE_MARGIN_SECONDS

    timeouts = timeouts or dict(DEFAULT_TIMEOUTS_SECONDS)

    common = dict(
        mongo=mongo,
        engine=engine,
        scope=scope,
        tenant=tenant,
        program_id=program_id,
    )  # each stage adds its own per-phase timeout
    core = dict(mongo=mongo, tenant=tenant, program_id=program_id)  # DB-only stages

    def inj(*keys: str) -> dict:
        return {k: injected[k] for k in keys if k in injected}

    enabled = set(enabled_modules)

    async def _disabled(_t: float = 0) -> dict:
        return {"skipped": True, "disabled": True, "note": "not enabled — turn on in settings"}

    def optional(module: str, real):
        """Run *real* (a zero-arg factory) only if the module is enabled; else the
        stage renders as a disabled node."""
        return real if module in enabled else _disabled

    # (name, coroutine factory) in execution order — the complete attacker chain.
    # OPTIONAL_MODULES stages (tls/service_scan/dork) self-skip when not enabled.
    # Each factory takes its per-stage timeout `t`. Tool stages forward it as their
    # tool budget; DB-only stages ignore it (bounded only by the wait_for ceiling).
    stage_defs: list[tuple[str, Any]] = [
        (
            "ingest",
            lambda t: run_ingest(
                **common, timeout=t, apex=apex, **inj("subfinder", "crtsh", "resolve")
            ),
        ),
        (
            "uncover",
            optional(
                "uncover",
                lambda t: run_uncover(
                    **common, apex=apex, timeout=t, search=injected.get("uncover_search")
                ),
            ),
        ),
        ("probe", lambda t: run_probe(**common, timeout=t, **inj("probe"))),
        ("tls", optional("tls", lambda t: run_tls_scan(**common, timeout=t, **inj("tlsinspect")))),
        ("takeover", lambda t: run_takeover(**common, timeout=t)),
        (
            "crawl",
            lambda t: run_crawl(**common, timeout=t, apex=apex, **inj("gau", "wayback", "katana")),
        ),
        (
            "content_discovery",
            lambda t: run_content_discovery(**common, timeout=t, **inj("discover")),
        ),
        ("port_scan", lambda t: run_port_scan(**common, timeout=t, **inj("naabu"))),
        (
            "service_scan",
            optional(
                "service_scan", lambda t: run_service_scan(**common, timeout=t, **inj("nmap"))
            ),
        ),
        ("scan", lambda t: run_scan(**common, timeout=t, **inj("scan"))),
        (
            "secrets",
            lambda t: run_secret_scan(
                mongo=mongo,
                engine=engine,
                scope=scope,
                tenant=tenant,
                program_id=program_id,
                **inj("fetch"),
            ),
        ),
        ("cve_watch", lambda t: run_cve_watch(**core, **inj("recent", "kev"))),
        ("github_osint", lambda t: run_github_leak_scan(**core, domain=apex, **inj("search"))),
        (
            "cloud_buckets",
            optional(
                "cloud_buckets",
                lambda t: run_cloud_buckets(
                    **core,
                    apex=apex,
                    **(
                        {"checker": injected["bucket_checker"]}
                        if "bucket_checker" in injected
                        else {}
                    ),
                ),
            ),
        ),
        (
            "nuclei_watch",
            optional(
                "nuclei_watch",
                lambda t: run_nuclei_watch(
                    **core,
                    **(
                        {"templates": injected["template_lister"]}
                        if "template_lister" in injected
                        else {}
                    ),
                ),
            ),
        ),
        (
            "dork",
            optional(
                "dork",
                lambda t: run_dork(
                    **core,
                    domain=apex,
                    **({"search": injected["dork_search"]} if "dork_search" in injected else {}),
                ),
            ),
        ),
        ("correlate", lambda t: run_correlate(**core)),
        ("notify", lambda t: run_notify(**core, **inj("senders"))),
    ]

    run = ScanRun(
        tenant_id=tenant.tenant_id,
        scan_id=scan_id,
        program_id=program_id,
        pipeline="full",
        status=ScanStatus.RUNNING,
        started_at=datetime.now(UTC),
        stages=[ScanStage(name=name) for name, _ in stage_defs],
    )
    await audit.save(run)

    results: dict[str, dict] = {}
    failed: list[str] = []  # stages that errored/timed out (run continues past them)
    with bind_context(tenant_id=tenant.tenant_id, scan_id=scan_id, program_id=program_id):
        logger.info("full scan started: {} ({} stages)", apex, len(stage_defs))
        for stage_obj, (name, factory) in zip(run.stages, stage_defs, strict=True):
            with bind_context(pipeline=name):
                stage_obj.status = ScanStatus.RUNNING
                stage_obj.started_at = datetime.now(UTC)
                await audit.save(run)  # flip to running so the poller sees the stage start
                # per-stage tool budget + a margin before the hard ceiling, so a tool's
                # own (graceful, partial-keeping) timeout fires before wait_for cancels.
                phase_timeout = timeouts.get(name, timeout)
                stage_budget = phase_timeout + STAGE_MARGIN_SECONDS
                logger.info("stage {} started (limit {:.0f}s)", name, phase_timeout)
                try:
                    res = await _run_stage_with_heartbeat(
                        factory(phase_timeout), budget=stage_budget, run=run, audit=audit
                    )
                except asyncio.CancelledError:
                    # Outer cancellation (the whole arq job is being killed) — persist
                    # FAILED (not stuck RUNNING) and abort the run.
                    now = datetime.now(UTC)
                    stage_obj.status = ScanStatus.FAILED
                    stage_obj.finished_at = now
                    run.status = ScanStatus.FAILED
                    run.finished_at = now
                    run.error = f"{name}: cancelled"
                    await asyncio.shield(audit.save(run))
                    logger.error("run cancelled for {} at stage {}", program_id, name)
                    raise
                except Exception as exc:  # noqa: BLE001
                    # ISOLATE a per-stage failure/timeout: mark this stage FAILED but
                    # keep going, so one flaky tool (e.g. a slow nmap) never sinks the
                    # whole run and lose scan/secrets/notify after it.
                    now = datetime.now(UTC)
                    timed_out = isinstance(exc, asyncio.TimeoutError)
                    stage_obj.status = ScanStatus.FAILED
                    stage_obj.finished_at = now
                    stage_obj.note = (
                        "timed out" if timed_out else f"{type(exc).__name__}: {exc}"[:200]
                    )
                    failed.append(name)
                    results[name] = {"failed": True, "note": stage_obj.note}
                    await audit.save(run)
                    # TimeoutError (and some cancellations) stringify to "", which made
                    # the log read "... failed (continuing): " — surface the type + note.
                    logger.error("stage {} failed (continuing): {}", name, stage_obj.note)
                    continue
                stage_obj.finished_at = datetime.now(UTC)
                if res.get("skipped"):
                    stage_obj.status = ScanStatus.SKIPPED
                    stage_obj.note = res.get("note")
                else:
                    stage_obj.status = ScanStatus.SUCCESS
                    stage_obj.stats = {k: v for k, v in res.items() if isinstance(v, int)}
                results[name] = res
                await audit.save(run)  # flip to done (+ stats/note) after the stage completes

        # The run is SUCCESS even if a non-fatal stage failed — every other stage ran
        # and its data was saved; the failed stage shows red in the stepper.
        run.status = ScanStatus.FAILED if failed else ScanStatus.SUCCESS
        run.finished_at = datetime.now(UTC)
        if failed:
            run.error = "stage(s) failed: " + ", ".join(failed)

        def _stat(stage: str, key: str) -> int:
            return int((results.get(stage) or {}).get(key, 0) or 0)

        run.stats = {
            "assets_new": _stat("ingest", "new"),
            "endpoints_new": (
                _stat("probe", "new") + _stat("crawl", "new") + _stat("content_discovery", "new")
            ),
            "ports_new": _stat("port_scan", "new"),
            "findings_new": _stat("scan", "new"),
            "secrets_new": _stat("secrets", "new"),
            "cve_matches": _stat("cve_watch", "new_alertable"),
            "issues": _stat("correlate", "count"),
        }
        await audit.save(run)
        return {"scan_id": scan_id, **results}


async def run_program(
    *,
    mongo: Any,
    engine: ScopeEngine,
    tenant: TenantContext,
    program_id: str,
    timeout: float,
    scan_id: str | None = None,
    force: bool = False,
    asn_ranges=None,
) -> dict:
    """Load program + authorization, enforce authorization, then run the pipeline.

    ``force`` = an explicit user-triggered scan, which runs even if monitoring is
    paused. Automated runs (scheduler bootstrap) leave it False, so a paused program
    is skipped — including a job that was already queued in Redis before the pause
    or a restart (the scheduler filters paused programs, but the queue may not)."""
    program = await ProgramRepo.from_mongo(mongo).get(tenant.tenant_id, program_id)
    if not program:
        raise AuthorizationRequired(f"no program {program_id} for tenant {tenant.tenant_id}")

    if not force and not program.get("enabled", True):
        logger.info(
            "program {} is paused (monitoring off) — skipping scheduled full run", program_id
        )
        return {"skipped": True, "note": "monitoring paused"}

    # §13 plan quota, re-checked here as well as at enqueue: a job that was queued
    # before a downgrade (or reaches the worker by any other path) must not burn
    # scan resources the tenant is no longer entitled to.
    if not await program_within_plan(mongo, tenant.tenant_id, program_id):
        logger.info("program {} is outside the tenant's plan allowance — skipping", program_id)
        return {"skipped": True, "note": "outside plan allowance"}

    auth = await AuthorizationRepo.from_mongo(mongo).get(tenant.tenant_id, program_id)
    if not _auth_is_current(auth):
        raise AuthorizationRequired(
            f"no current authorization for program {program_id}; refusing to scan"
        )

    auth = await confirm_authorization_ip_scope(
        mongo, program, auth, engine=engine, asn_ranges=asn_ranges
    )
    scope = build_program_scope(program, auth)
    # resolve per-stage timeouts: built-ins ← tenant defaults ← program overrides
    from db.tenants import TenantRepo
    from taskqueue.timeouts import effective_timeouts

    tenant_doc = await TenantRepo.from_mongo(mongo).get(tenant.tenant_id)
    timeouts = effective_timeouts(
        program.get("timeout_overrides"), (tenant_doc or {}).get("timeout_overrides")
    )
    result = await run_full_pipeline(
        mongo=mongo,
        engine=engine,
        scope=scope,
        tenant=tenant,
        program_id=program_id,
        apex=program["apex_domain"],
        timeout=timeout,
        scan_id=scan_id,
        enabled_modules=tuple(program.get("enabled_modules", [])),
        timeouts=timeouts,
    )
    # Once the first full run finishes, the scheduler switches this program from
    # bootstrap to per-phase cadence. Set only on the first completion.
    if program.get("initial_scan_completed_at") is None:
        await ProgramRepo.from_mongo(mongo).mark_initial_scan_completed(
            tenant.tenant_id, program_id, datetime.now(UTC)
        )
    return result
