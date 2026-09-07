"""Full-pipeline orchestration: ingest → probe → scan for one program.

This is what a worker runs for a program. It (1) refuses to proceed without a
current authorization record (§9b/§9e), (2) builds the ``ProgramScope`` from the
program + authorization, (3) runs the three pipelines in order, and (4) records a
``ScanRun`` audit row with per-stage stats.
"""

from __future__ import annotations

import asyncio
import contextlib
import uuid
from datetime import UTC, datetime
from typing import Any

from core import modules as module_registry
from core.errors import AuthorizationRequired, ScanCancelled
from core.logging import bind_context, logger
from core.metrics import REGISTRY
from core.models import ScanRun, ScanStage, ScanStatus
from core.ratelimit import PolitenessLimiter
from core.scope import ProgramScope, ScopeEngine, confirm_ip_scope, is_asn_confirmed
from core.tenant import TenantContext
from db.audit import ScanRunRepo
from db.authorizations import AuthorizationRepo
from db.programs import ProgramRepo
from pipelines.api_surface import run_api_surface
from pipelines.broken_links import run_broken_links
from pipelines.cloud_assets import run_cloud_assets
from pipelines.cloud_buckets import run_cloud_buckets
from pipelines.content_discovery import run_content_discovery
from pipelines.correlate import run_correlate
from pipelines.crawl import run_crawl
from pipelines.cve_watch import run_cve_watch
from pipelines.domain_intel import run_domain_intel
from pipelines.dork import run_dork
from pipelines.github_osint import run_github_leak_scan
from pipelines.http_misconfig import run_http_misconfig
from pipelines.ingest import run_ingest
from pipelines.js_mine import run_js_mine
from pipelines.notify import run_notify
from pipelines.nuclei_watch import run_nuclei_watch
from pipelines.param_discovery import run_param_discovery
from pipelines.port_scan import run_port_scan
from pipelines.probe import run_probe
from pipelines.reverse_dns import run_reverse_dns
from pipelines.scan import run_scan
from pipelines.secrets import run_secret_scan
from pipelines.service_scan import run_service_scan
from pipelines.supply_chain import run_supply_chain
from pipelines.takeover import run_takeover
from pipelines.tls import run_tls_scan
from pipelines.typosquat import run_typosquat
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


#: Buckets (seconds) for per-stage duration. Stages range from a sub-second
#: correlate to a 60-minute nuclei, so the spread is deliberately wide.
STAGE_DURATION_BUCKETS: tuple[float, ...] = (1, 5, 15, 60, 300, 900, 1800, 3600, 7200)


def _observe_stage(name: str, status: str, stage: ScanStage) -> None:
    """Record one stage's outcome + duration.

    This is the signal that catches a silent stall on an unattended run: a stage
    quietly flipping to ``timeout``, or its duration creeping toward its budget,
    is visible here long before a human notices missing findings.
    """
    REGISTRY.inc(
        "exactsurface_scan_stage_total",
        help="Scan stages by outcome",
        stage=name,
        status=status,
    )
    if stage.started_at and stage.finished_at:
        REGISTRY.observe(
            "exactsurface_scan_stage_duration_seconds",
            (stage.finished_at - stage.started_at).total_seconds(),
            help="Per-stage wall-clock duration",
            buckets=STAGE_DURATION_BUCKETS,
            stage=name,
        )


def _observe_run(run: ScanRun) -> None:
    REGISTRY.inc(
        "exactsurface_scan_run_total",
        help="Completed scan runs by pipeline and outcome",
        pipeline=run.pipeline,
        status=run.status.value,
    )
    if run.started_at and run.finished_at:
        REGISTRY.observe(
            "exactsurface_scan_run_duration_seconds",
            (run.finished_at - run.started_at).total_seconds(),
            help="Full-pipeline wall-clock duration",
            buckets=STAGE_DURATION_BUCKETS,
            pipeline=run.pipeline,
        )


#: how often to re-save a running ScanRun so its ``updated_at`` reflects liveness.
STAGE_HEARTBEAT_SECONDS = 45


async def _run_stage_with_heartbeat(
    coro, *, budget: float, run, audit, stage_name: str = "", cancel_check=None
) -> dict:
    """Await a stage coroutine with a hard *budget*, re-saving *run* every
    ``STAGE_HEARTBEAT_SECONDS`` so ``updated_at`` reflects that work is ongoing — a
    single stage (nuclei) can run for an hour, and without a heartbeat the UI would
    label an actively-working scan "stalled". Raises ``TimeoutError`` past the budget,
    propagates the stage's own exception, and re-raises an outer ``CancelledError``.

    The heartbeat tick is also where a user's **stop** request is noticed: ``cancel_check``
    is polled once per tick, and when it returns True the in-flight stage task is
    cancelled (which kills the running tool's subprocess — see ``modules.exec``) and
    :class:`ScanCancelled` is raised for the caller to finalise the run.
    """
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
            if cancel_check is not None and await cancel_check():
                task.cancel()
                # Let the cancellation propagate into the stage so its tool subprocess
                # is killed and its `finally` blocks run, before we unwind.
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await task
                raise ScanCancelled(stage_name)
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
    "domain_intel",  # passive: email spoofability + domain registration risk
    "ingest",
    "cloud_assets",  # optional — the operator's own cloud accounts
    "uncover",  # optional — Shodan/Censys passive discovery
    "reverse_dns",  # optional — PTR sweep of ASN-confirmed ranges
    "probe",
    "tls",  # optional
    "takeover",
    "crawl",
    "content_discovery",
    "js_mine",  # mine the app's own JavaScript for routes/hosts
    "api_surface",  # robots/sitemap/OpenAPI/GraphQL/.well-known
    "http_misconfig",  # CORS + open redirect + WAF context
    "param_discovery",  # optional — hidden query parameters
    "broken_links",  # hijackable outbound links
    "port_scan",
    "service_scan",  # optional
    "scan",
    "secrets",
    "cve_watch",
    "github_osint",
    "cloud_buckets",  # optional — S3/GCS/Azure permutation
    "nuclei_watch",  # optional — new template → targeted re-scan
    "dork",  # optional
    "supply_chain",  # dependency confusion from mined JS
    "typosquat",  # optional — registered lookalike domains
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
    disabled_modules: tuple[str, ...] = (),
    timeouts: dict[str, int] | None = None,
    # Explicit, NOT left to **injected: a swallowed kwarg here would silently mean
    # unthrottled requests at scanned hosts, which is the failure ADR-0012 fixes.
    limiter: PolitenessLimiter | None = None,
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

    # One resolver decides what runs. It honours opt-ins/opt-outs AND dependencies, so
    # a stage whose input module is off self-skips with that reason rather than running
    # against nothing and reporting a misleading zero.
    module_state = module_registry.resolve(
        enabled_modules=enabled_modules, disabled_modules=disabled_modules
    )

    def optional(_module: str, real):
        """Historically wrapped opt-in stages. Gating now happens once in the stage
        loop below — for EVERY stage, so a newly added one cannot forget it — leaving
        this as an identity that keeps the declarations below readable."""
        return real

    # (name, coroutine factory) in execution order — the complete attacker chain.
    # OPTIONAL_MODULES stages (tls/service_scan/dork) self-skip when not enabled.
    # Each factory takes its per-stage timeout `t`. Tool stages forward it as their
    # tool budget; DB-only stages ignore it (bounded only by the wait_for ceiling).
    stage_defs: list[tuple[str, Any]] = [
        (
            # Passive and instant: email spoofability + registration risk, straight from
            # DNS and the registry. Runs before anything touches a host.
            "domain_intel",
            lambda t: run_domain_intel(**core, apex=apex, **inj("resolve_txt", "rdap_fetch")),
        ),
        (
            "ingest",
            lambda t: run_ingest(
                **common, timeout=t, apex=apex, **inj("subfinder", "crtsh", "resolve")
            ),
        ),
        (
            # The strongest ownership signal available: the provider itself confirms
            # these are the operator's resources.
            "cloud_assets",
            optional(
                "cloud_assets",
                lambda t: run_cloud_assets(
                    mongo=mongo,
                    scope=scope,
                    tenant=tenant,
                    program_id=program_id,
                    timeout=t,
                    **inj("cloud_enumerate"),
                ),
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
        (
            # PTR sweep of ASN-confirmed ranges only — see pipelines/reverse_dns.py for
            # why this stage is the one with the most room to go wrong.
            "reverse_dns",
            optional(
                "reverse_dns",
                lambda t: run_reverse_dns(
                    mongo=mongo,
                    scope=scope,
                    tenant=tenant,
                    program_id=program_id,
                    timeout=t,
                    **inj("ptr_lookup"),
                ),
            ),
        ),
        ("probe", lambda t: run_probe(**common, timeout=t, **inj("probe"))),
        ("tls", optional("tls", lambda t: run_tls_scan(**common, timeout=t, **inj("tlsinspect")))),
        ("takeover", lambda t: run_takeover(**common, timeout=t, limiter=limiter)),
        (
            "crawl",
            lambda t: run_crawl(**common, timeout=t, apex=apex, **inj("gau", "wayback", "katana")),
        ),
        (
            "content_discovery",
            lambda t: run_content_discovery(**common, timeout=t, **inj("discover")),
        ),
        (
            # Reads the app's own JavaScript for routes/hosts the crawl never saw, and
            # feeds them back as endpoints for the stages below.
            "js_mine",
            lambda t: run_js_mine(**common, timeout=t, limiter=limiter, **inj("js_fetch")),
        ),
        (
            # Everything the host publishes about itself: robots, sitemap, API schema,
            # GraphQL introspection, .well-known. Feeds new endpoints back downstream.
            "api_surface",
            lambda t: run_api_surface(**common, timeout=t, limiter=limiter, **inj("api_fetch")),
        ),
        (
            "http_misconfig",
            lambda t: run_http_misconfig(
                **common, timeout=t, limiter=limiter, **inj("misconfig_fetch")
            ),
        ),
        (
            "param_discovery",
            optional(
                "param_discovery",
                lambda t: run_param_discovery(
                    **common, timeout=t, limiter=limiter, **inj("param_fetch")
                ),
            ),
        ),
        (
            # Needs the outbound links that crawl + js_mine collected.
            "broken_links",
            lambda t: run_broken_links(
                mongo=mongo,
                scope=scope,
                tenant=tenant,
                program_id=program_id,
                timeout=t,
                limiter=limiter,
                **inj("blh_resolve", "blh_status"),
            ),
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
                limiter=limiter,
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
        (
            # Reads the bundles js_mine recorded; no new discovery, pure analysis + npm.
            "supply_chain",
            lambda t: run_supply_chain(**core, timeout=t, **inj("pkg_fetch", "registry_status")),
        ),
        (
            "typosquat",
            optional(
                "typosquat",
                lambda t: run_typosquat(
                    **core, apex=apex, timeout=t, **inj("resolve_many", "resolve_mx_many")
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

    async def _cancel_requested() -> bool:
        """Has a user asked to stop this run? Read fresh from the DB — the API that
        records the request runs in a different process. Never let a DB blip look like
        a stop (that would abort a healthy scan), so failures answer 'no'."""
        try:
            return await audit.is_cancel_requested(tenant.tenant_id, scan_id)
        except Exception:  # noqa: BLE001 - a read failure must not abort a good run
            return False

    def _finalise_cancelled(current: ScanStage | None, stage_name: str) -> None:
        """Mark the in-flight stage and every stage after it as CANCELLED. Everything
        already discovered stays — each write was an idempotent upsert, so the data on
        disk is simply 'as far as the scan got'."""
        now = datetime.now(UTC)
        if current is not None:
            current.status = ScanStatus.CANCELLED
            current.finished_at = now
            current.note = "stopped by user"
        for pending in run.stages:
            if pending.status == ScanStatus.QUEUED:
                pending.status = ScanStatus.CANCELLED
                pending.note = "not run — scan stopped"
        run.status = ScanStatus.CANCELLED
        run.finished_at = now
        run.note = f"stopped by user during {stage_name}"

    with bind_context(tenant_id=tenant.tenant_id, scan_id=scan_id, program_id=program_id):
        logger.info("full scan started: {} ({} stages)", apex, len(stage_defs))
        for stage_obj, (name, factory) in zip(run.stages, stage_defs, strict=True):
            with bind_context(pipeline=name):
                # Cheap pre-stage check: catches a stop requested while the previous
                # stage was finishing, so we never start new work after a stop.
                if await _cancel_requested():
                    _finalise_cancelled(None, name)
                    _observe_run(run)
                    await audit.save(run)
                    logger.info("scan stopped by user before stage {}", name)
                    return {"scan_id": scan_id, "cancelled": True, **results}
                # One gate for every stage: honours the user's on/off choices AND the
                # dependency graph, so a stage whose input module is off is skipped with
                # that reason instead of running against nothing.
                if not module_state.is_enabled(name):
                    stage_obj.status = ScanStatus.SKIPPED
                    stage_obj.note = module_state.reason(name) or "not enabled"
                    stage_obj.finished_at = datetime.now(UTC)
                    results[name] = {"skipped": True, "disabled": True, "note": stage_obj.note}
                    _observe_stage(name, ScanStatus.SKIPPED.value, stage_obj)
                    await audit.save(run)
                    logger.info("stage {} skipped: {}", name, stage_obj.note)
                    continue
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
                        factory(phase_timeout),
                        budget=stage_budget,
                        run=run,
                        audit=audit,
                        stage_name=name,
                        cancel_check=_cancel_requested,
                    )
                except ScanCancelled:
                    # A user pressed stop. This is a clean outcome, not a failure: the
                    # in-flight tool has been killed, everything found so far is saved,
                    # and the run ends CANCELLED so a new scan can be started normally.
                    _finalise_cancelled(stage_obj, name)
                    _observe_stage(name, ScanStatus.CANCELLED.value, stage_obj)
                    _observe_run(run)
                    await audit.save(run)
                    logger.info("scan stopped by user during stage {}", name)
                    return {"scan_id": scan_id, "cancelled": True, **results}
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
                    _observe_stage(name, "timeout" if timed_out else "failed", stage_obj)
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
                _observe_stage(name, stage_obj.status.value, stage_obj)
                await audit.save(run)  # flip to done (+ stats/note) after the stage completes

        # The run is SUCCESS even if a non-fatal stage failed — every other stage ran
        # and its data was saved; the failed stage shows red in the stepper.
        run.status = ScanStatus.FAILED if failed else ScanStatus.SUCCESS
        run.finished_at = datetime.now(UTC)
        if failed:
            run.error = "stage(s) failed: " + ", ".join(failed)
        _observe_run(run)

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
    limiter: PolitenessLimiter | None = None,
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
        disabled_modules=tuple(program.get("disabled_modules", [])),
        timeouts=timeouts,
        limiter=limiter,
    )
    # Once the first full run finishes, the scheduler switches this program from
    # bootstrap to per-phase cadence. Set only on the first completion.
    if program.get("initial_scan_completed_at") is None:
        await ProgramRepo.from_mongo(mongo).mark_initial_scan_completed(
            tenant.tenant_id, program_id, datetime.now(UTC)
        )
    return result
