"""uncover pipeline — scope-gated Shodan/Censys discovery → assets + ports."""

from __future__ import annotations

from core.scope import ProgramScope, ScopeEngine
from core.tenant import TenantContext
from db.assets import AssetRepo
from db.ports import PortRepo
from pipelines.uncover import run_uncover
from tests.fakes import FakeMongo

ENGINE = ScopeEngine.from_data_file()
TENANT = TenantContext("t1", "u1")
# app.customer.com is dedicated; 45.55.0.0/16 is authorized for port-level intel.
SCOPE = ProgramScope(
    verified_apexes=("customer.com",), authorized_dedicated_cidrs=("45.55.0.0/16",)
)


async def test_uncover_scope_gates_results():
    mongo = FakeMongo()

    async def fake_search(_apex):
        return [
            "api.customer.com:443",  # in-scope hostname → asset
            "45.55.1.9:6379",  # authorized IP → port (exposed Redis)
            "8.8.8.8:53",  # unauthorized IP → dropped
            "evil.com:443",  # out-of-scope hostname → dropped
        ]

    res = await run_uncover(
        mongo=mongo,
        engine=ENGINE,
        scope=SCOPE,
        tenant=TENANT,
        program_id="p1",
        apex="customer.com",
        timeout=10,
        search=fake_search,
    )
    assert res["found"] == 4
    assert res["new_assets"] == 1 and res["new_ports"] == 1 and res["out_of_scope"] == 2
    assert res["cascade_targets"] == ["api.customer.com"]

    assets = await AssetRepo.from_mongo(mongo).list("t1", "p1")
    assert [a["hostname"] for a in assets] == ["api.customer.com"]
    assert assets[0]["source"] == "uncover"
    ports = await PortRepo.from_mongo(mongo).list("t1", "p1")
    assert len(ports) == 1 and ports[0]["ip"] == "45.55.1.9" and ports[0]["port"] == 6379


async def test_uncover_skips_without_keys():
    mongo = FakeMongo()  # no integration secrets configured
    res = await run_uncover(
        mongo=mongo,
        engine=ENGINE,
        scope=SCOPE,
        tenant=TENANT,
        program_id="p1",
        apex="customer.com",
        timeout=10,
    )
    assert res.get("skipped") and "API key" in res["note"]
    assert res["found"] == 0
