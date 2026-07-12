"""End-to-end pipeline tests (ingest → probe → scan) against fakes.

These prove the security-critical behaviours as a system, not just per-unit:
out-of-scope hosts are dropped, metadata-resolving hosts are never contacted, and
CDN/public hosts get safe scans while only confirmed-dedicated hosts get
aggressive scans.
"""

from __future__ import annotations

import pytest

from core.errors import AuthorizationRequired
from core.models import Authorization, IpScopeEntry, Program
from core.scope import ProgramScope, ScopeEngine
from core.tenant import TenantContext
from db.assets import AssetRepo
from db.audit import ScanRunRepo
from db.authorizations import AuthorizationRepo
from db.programs import ProgramRepo
from pipelines.ingest import run_ingest
from pipelines.orchestrate import build_program_scope, run_full_pipeline, run_program
from tests.fakes import FakeMongo

ENGINE = ScopeEngine.from_data_file()
TENANT = TenantContext(tenant_id="t1", actor_id="u1")
SCOPE = ProgramScope(
    verified_apexes=("customer.com",),
    authorized_dedicated_cidrs=("45.55.0.0/16",),
)

RESOLVE_MAP = {
    "customer.com": ["45.55.1.9"],  # dedicated
    "app.customer.com": ["45.55.1.1"],  # dedicated
    "www.customer.com": ["104.16.5.5"],  # cloudflare CDN
    "api.customer.com": ["8.8.8.8"],  # public, unconfirmed
    "evil.customer.com": ["169.254.169.254"],  # metadata — must never be contacted
}


async def fake_subfinder(_apex, _timeout):
    return ["app.customer.com", "www.customer.com", "evil.customer.com", "out.attacker.com"]


async def fake_crtsh(_apex):
    return ["api.customer.com"]


async def fake_resolve(hosts, _timeout):
    return {h: RESOLVE_MAP[h] for h in hosts if h in RESOLVE_MAP}


async def fake_probe(hosts, _timeout):
    return [
        {"url": f"https://{h}", "input": h, "status_code": 200, "title": "x", "tech": ["nginx"]}
        for h in hosts
    ]


def make_fake_scan(capture):
    async def fake_scan(urls, _timeout, aggressive=False, on_finding=None):
        capture.append({"urls": list(urls), "aggressive": aggressive})
        return [
            {
                "template_id": "exposed-env",
                "name": "Exposed .env",
                "severity": "high",
                "matched_at": u,
                "description": "",
                "reference": [],
                "raw": {},
            }
            for u in urls
        ]

    return fake_scan


async def fake_gau(_apex, _t):
    return []


async def fake_wayback(_apex, _t):
    return []


async def fake_katana(_url, _t):
    return []


async def fake_fetch(_url):
    return ""


async def fake_discover(_url, _wordlist, _t):
    return []


async def fake_naabu(_hosts, _t):
    return []


async def fake_recent_cves():
    return []


async def fake_kev():
    return set()


def _injected(scan_capture):
    return dict(
        subfinder=fake_subfinder,
        crtsh=fake_crtsh,
        resolve=fake_resolve,
        probe=fake_probe,
        gau=fake_gau,
        wayback=fake_wayback,
        katana=fake_katana,
        discover=fake_discover,
        naabu=fake_naabu,
        scan=make_fake_scan(scan_capture),
        fetch=fake_fetch,
        recent=fake_recent_cves,
        kev=fake_kev,
    )


async def test_ingest_drops_out_of_scope_hosts():
    mongo = FakeMongo()
    res = await run_ingest(
        mongo=mongo,
        engine=ENGINE,
        scope=SCOPE,
        tenant=TENANT,
        program_id="p1",
        apex="customer.com",
        timeout=10,
        subfinder=fake_subfinder,
        crtsh=fake_crtsh,
        resolve=fake_resolve,
    )
    assert "out.attacker.com" not in res["new_hosts"]  # not under apex
    assert set(res["new_hosts"]) == {
        "customer.com",
        "app.customer.com",
        "www.customer.com",
        "api.customer.com",
        "evil.customer.com",
    }


async def test_full_pipeline_scope_enforcement():
    mongo = FakeMongo()
    scan_calls: list[dict] = []
    result = await run_full_pipeline(
        mongo=mongo,
        engine=ENGINE,
        scope=SCOPE,
        tenant=TENANT,
        program_id="p1",
        apex="customer.com",
        timeout=10,
        **_injected(scan_calls),
    )

    # evil.customer.com resolves to the metadata IP → never probed or scanned.
    all_scanned = [u for call in scan_calls for u in call["urls"]]
    assert not any("evil.customer.com" in u for u in all_scanned)
    assert result["probe"]["alive"] == 4  # app, www, api, apex — not evil

    # Aggressive scans only against confirmed-dedicated hosts; CDN/public → safe.
    aggressive = {u for call in scan_calls if call["aggressive"] for u in call["urls"]}
    safe = {u for call in scan_calls if not call["aggressive"] for u in call["urls"]}
    assert aggressive == {"https://app.customer.com", "https://customer.com"}
    assert safe == {"https://www.customer.com", "https://api.customer.com"}


async def test_full_pipeline_is_idempotent():
    mongo = FakeMongo()
    first = await run_full_pipeline(
        mongo=mongo,
        engine=ENGINE,
        scope=SCOPE,
        tenant=TENANT,
        program_id="p1",
        apex="customer.com",
        timeout=10,
        **_injected([]),
    )
    second = await run_full_pipeline(
        mongo=mongo,
        engine=ENGINE,
        scope=SCOPE,
        tenant=TENANT,
        program_id="p1",
        apex="customer.com",
        timeout=10,
        **_injected([]),
    )
    assert first["ingest"]["new"] > 0
    assert second["ingest"]["new"] == 0  # nothing new the second time
    assert second["scan"]["new"] == 0
    assert await AssetRepo(mongo.collection("assets")).count("t1") == 5  # no duplicates


async def test_full_pipeline_records_per_stage_progress():

    mongo = FakeMongo()
    result = await run_full_pipeline(
        mongo=mongo,
        engine=ENGINE,
        scope=SCOPE,
        tenant=TENANT,
        program_id="p1",
        apex="customer.com",
        timeout=10,
        **_injected([]),
    )
    run = await mongo.collection("scan_runs").find_one({"scan_id": result["scan_id"]})
    assert run["status"] == "success"
    names = [s["name"] for s in run["stages"]]
    assert names == [
        "ingest",
        "uncover",
        "probe",
        "tls",
        "takeover",
        "crawl",
        "content_discovery",
        "port_scan",
        "service_scan",
        "scan",
        "secrets",
        "cve_watch",
        "github_osint",
        "dork",
        "correlate",
        "notify",
    ]
    # early stages ran with data; the rest either ran or skipped, none failed
    assert all(s["status"] in ("success", "skipped") for s in run["stages"])
    by = {s["name"]: s for s in run["stages"]}
    assert by["ingest"]["status"] == "success"
    # optional modules are off by default → rendered as a disabled/skipped node
    assert (
        by["tls"]["status"] == "skipped"
        and by["tls"]["note"] == "not enabled — turn on in settings"
    )
    assert by["service_scan"]["status"] == "skipped"
    assert by["dork"]["status"] == "skipped"


async def test_program_bootstraps_as_soon_as_ingest_succeeds():
    # A slow later stage (nuclei) that gets interrupted must not leave the program stuck
    # re-bootstrapping — the baseline is set the moment discovery runs.
    mongo = FakeMongo()
    await ProgramRepo.from_mongo(mongo).save(
        Program(tenant_id="t1", program_id="p1", apex_domain="customer.com", verified=True)
    )
    assert (await ProgramRepo.from_mongo(mongo).get("t1", "p1"))[
        "initial_scan_completed_at"
    ] is None

    await run_full_pipeline(
        mongo=mongo,
        engine=ENGINE,
        scope=SCOPE,
        tenant=TENANT,
        program_id="p1",
        apex="customer.com",
        timeout=10,
        **_injected([]),
    )
    prog = await ProgramRepo.from_mongo(mongo).get("t1", "p1")
    assert prog["initial_scan_completed_at"] is not None  # bootstrapped after ingest


async def test_enabled_optional_module_runs():
    mongo = FakeMongo()

    tls_calls: list = []

    async def fake_tls(hosts, _t):
        tls_calls.append(list(hosts))
        return []

    result = await run_full_pipeline(
        mongo=mongo,
        engine=ENGINE,
        scope=SCOPE,
        tenant=TENANT,
        program_id="p1",
        apex="customer.com",
        timeout=10,
        enabled_modules=("tls",),
        tlsinspect=fake_tls,
        **_injected([]),
    )
    run = await mongo.collection("scan_runs").find_one({"scan_id": result["scan_id"]})
    by = {s["name"]: s for s in run["stages"]}
    assert by["tls"]["status"] == "success"  # enabled → ran (not the disabled note)
    assert tls_calls  # tlsx actually invoked on the probeable hosts
    assert by["service_scan"]["status"] == "skipped"  # still off
    # per-stage stats captured (ingest discovered assets)
    ingest_stage = next(s for s in run["stages"] if s["name"] == "ingest")
    assert ingest_stage["stats"].get("new", 0) > 0
    # sanity: only one run row for this scan
    assert len(await ScanRunRepo.from_mongo(mongo).list("t1")) == 1


async def test_full_pipeline_isolates_failing_stage_and_continues():
    # A stage that raises marks itself FAILED but the run CONTINUES — one flaky tool
    # must not sink the whole scan (losing secrets/notify after it).
    mongo = FakeMongo()

    async def boom_scan(_urls, _t, aggressive=False):
        raise RuntimeError("scanner exploded")

    injected = _injected([]) | {"scan": boom_scan}
    result = await run_full_pipeline(
        mongo=mongo,
        engine=ENGINE,
        scope=SCOPE,
        tenant=TENANT,
        program_id="p1",
        apex="customer.com",
        timeout=10,
        **injected,
    )
    assert "scan_id" in result  # returned normally (no raise)
    run = await mongo.collection("scan_runs").find_one({"program_id": "p1"})
    assert run["status"] == "failed" and "scan" in run["error"]
    by_name = {s["name"]: s["status"] for s in run["stages"]}
    assert by_name["ingest"] == "success"
    assert by_name["scan"] == "failed"
    # stages AFTER the failed one still ran (not left queued)
    assert by_name["secrets"] != "queued"
    assert by_name["notify"] != "queued"


async def test_full_pipeline_stage_timeout_fails_cleanly_not_stalls():
    import asyncio

    import taskqueue.timeouts as tmo

    # tiny per-stage ceiling so a slow stage trips it instantly: drop the margin and
    # set the probe phase's configured timeout to 20ms via the `timeouts` arg.
    orig_margin = tmo.STAGE_MARGIN_SECONDS
    tmo.STAGE_MARGIN_SECONDS = 0
    try:

        async def slow_probe(_hosts, _t):
            await asyncio.sleep(0.5)
            return []

        mongo = FakeMongo()
        injected = _injected([]) | {"probe": slow_probe}
        # a stuck stage times out cleanly (FAILED, not stuck RUNNING) and the run
        # continues past it rather than aborting.
        await run_full_pipeline(
            mongo=mongo,
            engine=ENGINE,
            scope=SCOPE,
            tenant=TENANT,
            program_id="p1",
            apex="customer.com",
            timeout=10,
            timeouts={"probe": 0.02},
            **injected,
        )
    finally:
        tmo.STAGE_MARGIN_SECONDS = orig_margin

    run = await mongo.collection("scan_runs").find_one({"program_id": "p1"})
    assert run["status"] == "failed" and "probe" in run["error"]
    by_name = {s["name"]: s for s in run["stages"]}
    assert by_name["ingest"]["status"] == "success"  # ran before the stuck stage
    assert by_name["probe"]["status"] == "failed"  # timed out → FAILED, not RUNNING
    assert by_name["probe"]["note"] == "timed out"
    assert by_name["notify"]["status"] != "queued"  # later stages still ran


async def test_run_program_requires_authorization():
    mongo = FakeMongo()
    await ProgramRepo.from_mongo(mongo).save(
        Program(tenant_id="t1", program_id="p1", apex_domain="customer.com", verified=True)
    )
    # No authorization record yet → must refuse.
    with pytest.raises(AuthorizationRequired):
        await run_program(mongo=mongo, engine=ENGINE, tenant=TENANT, program_id="p1", timeout=10)


async def test_build_program_scope_extracts_dedicated_cidrs():
    program = Program(
        tenant_id="t1",
        program_id="p1",
        apex_domain="customer.com",
        excluded_hosts=["legacy.customer.com"],
    ).model_dump(mode="json")
    auth = Authorization(
        tenant_id="t1",
        program_id="p1",
        authorized_by="u1",
        apex_verified=True,
        ip_scope=[
            IpScopeEntry(
                cidr="45.55.0.0/16",
                ip_class="dedicated",
                action_set=["port_scan"],
                confirmed_via="whois:AS14061",
            )
        ],
    ).model_dump(mode="json")
    scope = build_program_scope(program, auth)
    assert scope.authorized_dedicated_cidrs == ("45.55.0.0/16",)
    assert "legacy.customer.com" in scope.excluded_hosts


async def test_paused_program_skips_automated_full_run():
    # A paused (enabled=False) program must NOT run on the automated bootstrap path.
    mongo = FakeMongo()
    await ProgramRepo.from_mongo(mongo).save(
        Program(
            tenant_id="t1",
            program_id="p1",
            apex_domain="customer.com",
            verified=True,
            enabled=False,
        )
    )
    await AuthorizationRepo.from_mongo(mongo).save(
        Authorization(tenant_id="t1", program_id="p1", authorized_by="u", apex_verified=True)
    )
    res = await run_program(mongo=mongo, engine=ENGINE, tenant=TENANT, program_id="p1", timeout=10)
    assert res.get("skipped") and res.get("note") == "monitoring paused"
    # no ScanRun was created (the run never started)
    assert await mongo.collection("scan_runs").find_one({"program_id": "p1"}) is None


async def test_paused_program_still_runs_when_forced():
    # An explicit user scan (force=True) runs even if monitoring is paused.
    mongo = FakeMongo()
    await ProgramRepo.from_mongo(mongo).save(
        Program(
            tenant_id="t1",
            program_id="p1",
            apex_domain="customer.com",
            verified=True,
            enabled=False,
        )
    )
    await AuthorizationRepo.from_mongo(mongo).save(
        Authorization(tenant_id="t1", program_id="p1", authorized_by="u", apex_verified=True)
    )

    # stub the heavy pipeline so we only assert force bypasses the pause gate
    import pipelines.orchestrate as orch

    async def _stub(**_kw):
        return {"ran": True}

    orig = orch.run_full_pipeline
    orch.run_full_pipeline = _stub
    try:
        res = await run_program(
            mongo=mongo, engine=ENGINE, tenant=TENANT, program_id="p1", timeout=10, force=True
        )
    finally:
        orch.run_full_pipeline = orig
    assert res == {"ran": True}  # bypassed the pause and ran the pipeline
