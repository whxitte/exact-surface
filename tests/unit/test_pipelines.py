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
    async def fake_scan(urls, _timeout, aggressive=False):
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


def _injected(scan_capture):
    return dict(
        subfinder=fake_subfinder,
        crtsh=fake_crtsh,
        resolve=fake_resolve,
        probe=fake_probe,
        gau=fake_gau,
        wayback=fake_wayback,
        katana=fake_katana,
        scan=make_fake_scan(scan_capture),
        fetch=fake_fetch,
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
    from db.audit import ScanRunRepo

    mongo = FakeMongo()
    result = await run_full_pipeline(
        mongo=mongo, engine=ENGINE, scope=SCOPE, tenant=TENANT,
        program_id="p1", apex="customer.com", timeout=10, **_injected([]),
    )
    run = await mongo.collection("scan_runs").find_one({"scan_id": result["scan_id"]})
    assert run["status"] == "success"
    names = [s["name"] for s in run["stages"]]
    assert names == ["ingest", "probe", "crawl", "scan", "secrets"]
    assert all(s["status"] == "success" for s in run["stages"])
    # per-stage stats captured (ingest discovered assets)
    ingest_stage = next(s for s in run["stages"] if s["name"] == "ingest")
    assert ingest_stage["stats"].get("new", 0) > 0
    # sanity: only one run row for this scan
    assert len(await ScanRunRepo.from_mongo(mongo).list("t1")) == 1


async def test_full_pipeline_marks_failing_stage_and_leaves_later_stages_queued():
    mongo = FakeMongo()

    async def boom_scan(_urls, _t, aggressive=False):
        raise RuntimeError("scanner exploded")

    injected = _injected([]) | {"scan": boom_scan}
    with pytest.raises(RuntimeError, match="scanner exploded"):
        await run_full_pipeline(
            mongo=mongo, engine=ENGINE, scope=SCOPE, tenant=TENANT,
            program_id="p1", apex="customer.com", timeout=10, **injected,
        )
    run = await mongo.collection("scan_runs").find_one({"program_id": "p1"})
    assert run["status"] == "failed" and run["error"].startswith("scan:")
    by_name = {s["name"]: s["status"] for s in run["stages"]}
    assert by_name["ingest"] == "success"
    assert by_name["probe"] == "success"
    assert by_name["crawl"] == "success"
    assert by_name["scan"] == "failed"
    assert by_name["secrets"] == "queued"  # never reached


async def test_full_pipeline_stage_timeout_fails_cleanly_not_stalls():
    import asyncio
    from types import SimpleNamespace

    import pipelines.orchestrate as orch

    # tiny per-stage ceiling so a slow stage trips it instantly
    orig = orch.get_settings
    orch.get_settings = lambda: SimpleNamespace(stage_timeout=0.02)
    try:

        async def slow_probe(_hosts, _t):
            await asyncio.sleep(0.5)
            return []

        mongo = FakeMongo()
        injected = _injected([]) | {"probe": slow_probe}
        with pytest.raises(asyncio.TimeoutError):
            await run_full_pipeline(
                mongo=mongo, engine=ENGINE, scope=SCOPE, tenant=TENANT,
                program_id="p1", apex="customer.com", timeout=10, **injected,
            )
    finally:
        orch.get_settings = orig

    run = await mongo.collection("scan_runs").find_one({"program_id": "p1"})
    assert run["status"] == "failed" and run["error"] == "probe: timed out"
    by_name = {s["name"]: s["status"] for s in run["stages"]}
    assert by_name["ingest"] == "success"  # ran before the stuck stage
    assert by_name["probe"] == "failed"  # timed out → FAILED, not left RUNNING
    assert by_name["crawl"] == "queued"  # never reached


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
