"""Crawl pipeline — scope-filtered endpoint discovery."""

from __future__ import annotations

from core.hashing import asset_fingerprint
from core.models import Asset
from core.scope import ProgramScope, ScopeEngine
from core.tenant import TenantContext
from db.assets import AssetRepo
from db.endpoints import EndpointRepo
from pipelines.crawl import run_crawl
from tests.fakes import FakeMongo

ENGINE = ScopeEngine.from_data_file()
TENANT = TenantContext("t1", "u1")
SCOPE = ProgramScope(
    verified_apexes=("customer.com",), authorized_dedicated_cidrs=("45.55.0.0/16",)
)


async def _seed_asset(mongo, hostname, ips):
    await AssetRepo(mongo.collection("assets")).upsert(
        Asset(
            tenant_id="t1",
            program_id="p1",
            fingerprint=asset_fingerprint("p1", hostname),
            hostname=hostname,
            resolved_ips=ips,
        )
    )


async def test_crawl_filters_out_of_scope_and_gates_active_crawl():
    mongo = FakeMongo()
    await _seed_asset(mongo, "app.customer.com", ["45.55.1.1"])  # HTTP_PROBE ok → katana
    await _seed_asset(mongo, "evil.customer.com", ["169.254.169.254"])  # denied → no katana

    async def gau(_apex, _t):
        return ["https://app.customer.com/a", "https://evil.attacker.com/x"]

    async def wayback(_apex, _t):
        return ["https://api.customer.com/b"]

    katana_targets: list[str] = []

    async def katana(url, _t):
        katana_targets.append(url)
        return [f"{url}/admin"]

    await run_crawl(
        mongo=mongo,
        engine=ENGINE,
        scope=SCOPE,
        tenant=TENANT,
        program_id="p1",
        apex="customer.com",
        timeout=10,
        gau=gau,
        wayback=wayback,
        katana=katana,
    )

    # active crawl only for the HTTP-permitted host, never the metadata one
    assert katana_targets == ["https://app.customer.com"]

    urls = {e["url"] for e in await EndpointRepo(mongo.collection("endpoints")).list("t1", "p1")}
    assert "https://app.customer.com/a" in urls
    assert "https://api.customer.com/b" in urls
    assert "https://app.customer.com/admin" in urls  # from katana
    assert not any("attacker.com" in u for u in urls)  # out-of-scope dropped
