"""Crawl pipeline — scope-filtered endpoint discovery."""

from __future__ import annotations

from core.hashing import asset_fingerprint, endpoint_fingerprint
from core.models import Asset, Endpoint
from core.scope import ProgramScope, ScopeEngine
from core.tenant import TenantContext
from db.assets import AssetRepo
from db.endpoints import EndpointRepo
from pipelines.crawl import (
    MAX_ACTIVE_CRAWL_HOSTS,
    MAX_HOST_CRAWL_SECONDS,
    run_crawl,
)
from tests.fakes import FakeMongo

ENGINE = ScopeEngine.from_data_file()
TENANT = TenantContext("t1", "u1")
SCOPE = ProgramScope(
    verified_apexes=("customer.com",), authorized_dedicated_cidrs=("45.55.0.0/16",)
)


async def _seed_asset(mongo, hostname, ips, *, alive=True):
    await AssetRepo(mongo.collection("assets")).upsert(
        Asset(
            tenant_id="t1",
            program_id="p1",
            fingerprint=asset_fingerprint("p1", hostname),
            hostname=hostname,
            resolved_ips=ips,
        )
    )
    # Active katana crawl now runs only on hosts PROBE found alive — represented by a
    # probe-sourced root endpoint. Seed one by default so existing scenarios crawl.
    if alive:
        url = f"https://{hostname}"
        await EndpointRepo(mongo.collection("endpoints")).upsert(
            Endpoint(
                tenant_id="t1",
                program_id="p1",
                fingerprint=endpoint_fingerprint("p1", "GET", url),
                url=url,
                source="probe",
                status_code=200,
            )
        )


async def test_crawl_filters_out_of_scope_and_gates_active_crawl():
    mongo = FakeMongo()
    await _seed_asset(mongo, "app.customer.com", ["45.55.1.1"])  # HTTP_PROBE ok → katana
    await _seed_asset(mongo, "evil.customer.com", ["169.254.169.254"])  # denied → no katana
    # In scope + HTTP-permitted, but PROBE never found it alive (no probe endpoint) —
    # katana must skip it rather than waste the run timing out on a dead host.
    await _seed_asset(mongo, "dead.customer.com", ["45.55.1.2"], alive=False)

    async def gau(_apex, _t):
        return ["https://app.customer.com/a", "https://evil.attacker.com/x"]

    async def wayback(_apex, _t):
        return ["https://api.customer.com/b"]

    katana_targets: list[str] = []

    async def katana(url, _t, *, rate=None):
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

    # active crawl only for the probed-alive HTTP-permitted host — never the metadata
    # one, and never the dead (unprobed) one
    assert katana_targets == ["https://app.customer.com"]

    urls = {e["url"] for e in await EndpointRepo(mongo.collection("endpoints")).list("t1", "p1")}
    assert "https://app.customer.com/a" in urls
    assert "https://api.customer.com/b" in urls
    assert "https://app.customer.com/admin" in urls  # from katana
    assert not any("attacker.com" in u for u in urls)  # out-of-scope dropped


async def test_crawl_caps_active_hosts_and_bounds_per_host_timeout():
    mongo = FakeMongo()
    # more in-scope, HTTP-permitted hosts than the active-crawl cap
    for i in range(MAX_ACTIVE_CRAWL_HOSTS + 10):
        await _seed_asset(mongo, f"h{i}.customer.com", ["45.55.1.1"])

    calls: list[tuple[str, float]] = []

    async def katana(url, t, *, rate=None):
        calls.append((url, t))
        return []

    async def empty(_apex, _t):
        return []

    await run_crawl(
        mongo=mongo,
        engine=ENGINE,
        scope=SCOPE,
        tenant=TENANT,
        program_id="p1",
        apex="customer.com",
        timeout=300,
        gau=empty,
        wayback=empty,
        katana=katana,
    )

    # never crawl more hosts than the cap, and each host gets the small slice,
    # not the full 300s tool budget (that was the full-run timeout bug).
    assert len(calls) == MAX_ACTIVE_CRAWL_HOSTS
    assert all(t == MAX_HOST_CRAWL_SECONDS for _, t in calls)
