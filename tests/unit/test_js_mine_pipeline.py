"""The JS-mine stage: mines in-scope bundles, records them, and feeds paths back.

The compounding behaviour is the point — routes the app names in its own JavaScript
become endpoints the rest of the pipeline then probes and scans.
"""

from __future__ import annotations

from core.hashing import asset_fingerprint, endpoint_fingerprint
from core.models import Asset, Endpoint
from core.scope import ProgramScope, ScopeEngine
from core.tenant import TenantContext
from db.assets import AssetRepo
from db.endpoints import EndpointRepo
from db.findings import FindingRepo
from db.jsfiles import JsFileRepo
from pipelines.js_mine import run_js_mine
from tests.fakes import FakeMongo

ENGINE = ScopeEngine.from_data_file()
TENANT = TenantContext("t1", "u1")
SCOPE = ProgramScope(verified_apexes=("customer.com",))

BUNDLE = """
const A="/api/internal/v2/users";
fetch("/admin/settings");
axios.get("https://api.customer.com/private/keys");
//# sourceMappingURL=main.js.map
"""


async def _seed_js(mongo, url: str, *, host: str = "customer.com") -> None:
    # A real run always has the asset (ingest creates it); scope needs its IPs to
    # decide whether we may contact the host at all.
    await AssetRepo(mongo.collection("assets")).upsert(
        Asset(
            tenant_id="t1",
            program_id="p1",
            fingerprint=asset_fingerprint("p1", host),
            hostname=host,
            resolved_ips=["93.184.216.34"],
        )
    )
    await EndpointRepo(mongo.collection("endpoints")).upsert(
        Endpoint(
            tenant_id="t1",
            program_id="p1",
            fingerprint=endpoint_fingerprint("p1", "GET", url),
            url=url,
            source="crawl",
        )
    )


async def _run(mongo, **kw):
    async def fetch(_url):
        return BUNDLE

    return await run_js_mine(
        mongo=mongo, engine=ENGINE, scope=SCOPE, tenant=TENANT,
        program_id="p1", fetch=kw.pop("fetch", fetch), **kw,
    )


async def test_mines_bundle_and_records_it():
    mongo = FakeMongo()
    await _seed_js(mongo, "https://customer.com/static/main.js")
    result = await _run(mongo)

    assert result["files"] == 1
    files = await JsFileRepo.from_mongo(mongo).list("t1", "p1", limit=10)
    assert files[0]["source_map"] == "https://customer.com/static/main.js.map"
    assert files[0]["interesting_count"] >= 2


async def test_discovered_paths_become_endpoints():
    """The compounding step: JS routes become endpoints for later stages."""
    mongo = FakeMongo()
    await _seed_js(mongo, "https://customer.com/static/main.js")
    await _run(mongo)

    urls = {e["url"] for e in await EndpointRepo.from_mongo(mongo).list("t1", "p1", limit=100)}
    assert "https://customer.com/api/internal/v2/users" in urls
    assert "https://customer.com/admin/settings" in urls
    eps = await EndpointRepo.from_mongo(mongo).list("t1", "p1", limit=100)
    sources = {e["source"] for e in eps}
    assert "js" in sources  # visible in the Endpoints tab's source filter


async def test_source_map_and_sensitive_routes_raise_findings():
    mongo = FakeMongo()
    await _seed_js(mongo, "https://customer.com/static/main.js")
    await _run(mongo)

    findings = await FindingRepo.from_mongo(mongo).list("t1", "p1", limit=100)
    checks = {f["check_id"] for f in findings}
    assert "js-source-map-exposed" in checks
    assert "js-sensitive-route" in checks


async def test_third_party_bundles_are_not_fetched():
    """A CDN's JS is not ours to read or report on."""
    mongo = FakeMongo()
    await _seed_js(mongo, "https://cdn.thirdparty.io/app.js", host="cdn.thirdparty.io")
    fetched: list[str] = []

    async def spy(url):
        fetched.append(url)
        return BUNDLE

    result = await _run(mongo, fetch=spy)
    assert fetched == []
    assert result.get("skipped") is True


async def test_library_bundles_are_skipped():
    mongo = FakeMongo()
    await _seed_js(mongo, "https://customer.com/js/jquery-3.6.0.min.js")
    result = await _run(mongo)
    assert result.get("skipped") is True  # nothing worth mining
