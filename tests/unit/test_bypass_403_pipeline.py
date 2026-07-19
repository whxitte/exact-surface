"""The on-demand 403-bypass runner (pipelines.bypass_403).

Verifies it only tests forbidden, in-scope, live endpoints, records results onto the
endpoint out-of-band, and skips out-of-scope hosts — all against a FakeMongo and a fake
probe (no network).
"""

from __future__ import annotations

from core.hashing import asset_fingerprint, endpoint_fingerprint
from core.models import Asset, Endpoint
from core.scope import ProgramScope, ScopeEngine
from core.tenant import TenantContext
from db.assets import AssetRepo
from db.endpoints import EndpointRepo
from modules.http_bypass import ProbeResult
from pipelines.bypass_403 import run_bypass_403
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


async def _seed_endpoint(mongo, url, status_code):
    fp = endpoint_fingerprint("p1", "GET", url)
    await EndpointRepo(mongo.collection("endpoints")).upsert(
        Endpoint(
            tenant_id="t1",
            program_id="p1",
            fingerprint=fp,
            url=url,
            source="probe",
            status_code=status_code,
        )
    )
    return fp


def _probe_200_on_header(header: str):
    async def probe(url, method, headers):
        if header in headers:
            return ProbeResult(200, 4096, "ADMIN")
        return ProbeResult(403, 100, "Forbidden")

    return probe


async def test_records_bypass_on_forbidden_in_scope_endpoint():
    mongo = FakeMongo()
    await _seed_asset(mongo, "app.customer.com", ["45.55.1.1"])
    fp = await _seed_endpoint(mongo, "https://app.customer.com/admin", 403)

    result = await run_bypass_403(
        mongo=mongo,
        engine=ENGINE,
        scope=SCOPE,
        tenant=TENANT,
        program_id="p1",
        probe=_probe_200_on_header("X-Original-URL"),
    )
    assert result["endpoints"] == 1
    assert result["bypassed"] == 1

    ep = await EndpointRepo(mongo.collection("endpoints")).get("t1", fp)
    assert ep["bypass_attempted"] is True
    assert ep["bypasses"], "bypass results should be attached to the endpoint"
    assert ep["bypass_checked_at"] is not None


async def test_ignores_non_forbidden_endpoints():
    mongo = FakeMongo()
    await _seed_asset(mongo, "app.customer.com", ["45.55.1.1"])
    await _seed_endpoint(mongo, "https://app.customer.com/", 200)  # already public

    result = await run_bypass_403(
        mongo=mongo,
        engine=ENGINE,
        scope=SCOPE,
        tenant=TENANT,
        program_id="p1",
        probe=_probe_200_on_header("X-Original-URL"),
    )
    assert result.get("skipped") is True
    assert result["endpoints"] == 0


async def test_skips_out_of_scope_host():
    mongo = FakeMongo()
    # A 403 endpoint whose host is NOT under the verified apex — must never be probed.
    fp = await _seed_endpoint(mongo, "https://not-ours.attacker.com/admin", 403)

    probed: list[str] = []

    async def spy_probe(url, method, headers):
        probed.append(url)
        return ProbeResult(403, 100, "Forbidden")

    result = await run_bypass_403(
        mongo=mongo,
        engine=ENGINE,
        scope=SCOPE,
        tenant=TENANT,
        program_id="p1",
        probe=spy_probe,
    )
    assert probed == [], "out-of-scope host must not be contacted"
    assert result["endpoints"] == 0
    ep = await EndpointRepo(mongo.collection("endpoints")).get("t1", fp)
    assert not ep.get("bypass_attempted")


async def test_records_empty_result_when_no_bypass_found():
    mongo = FakeMongo()
    await _seed_asset(mongo, "app.customer.com", ["45.55.1.1"])
    fp = await _seed_endpoint(mongo, "https://app.customer.com/admin", 403)

    async def always_403(url, method, headers):
        return ProbeResult(403, 100, "Forbidden")

    result = await run_bypass_403(
        mongo=mongo,
        engine=ENGINE,
        scope=SCOPE,
        tenant=TENANT,
        program_id="p1",
        probe=always_403,
    )
    assert result["endpoints"] == 1
    assert result["bypassed"] == 0
    ep = await EndpointRepo(mongo.collection("endpoints")).get("t1", fp)
    assert ep["bypass_attempted"] is True  # we tried
    assert ep["bypasses"] == []  # but found nothing
