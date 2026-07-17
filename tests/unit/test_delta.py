"""Delta detection — state-change events (the core differentiator)."""

from __future__ import annotations

from core.hashing import asset_fingerprint
from core.models import Asset, Endpoint
from core.scope import ProgramScope, ScopeEngine
from core.tenant import TenantContext
from db.assets import AssetRepo
from db.deltas import DeltaRepo
from modules.intelligence.delta_monitor import compute_endpoint_deltas
from pipelines.probe import run_probe
from tests.fakes import FakeMongo

ENGINE = ScopeEngine.from_data_file()
TENANT = TenantContext("t1", "u1")
SCOPE = ProgramScope(
    verified_apexes=("customer.com",), authorized_dedicated_cidrs=("45.55.0.0/16",)
)


def _ep(status, tech, content_hash):
    return Endpoint(
        tenant_id="t1",
        program_id="p1",
        fingerprint="fp",
        url="https://app.customer.com",
        status_code=status,
        tech=tech,
        content_hash=content_hash,
    )


def test_new_endpoint_has_no_deltas():
    assert compute_endpoint_deltas("t1", "p1", None, _ep(200, [], "a")) == []


def test_status_and_tech_and_title_changes():
    old = {"status_code": 403, "tech": ["nginx"], "content_hash": "a", "title": "Forbidden"}
    kinds = {
        d.kind.value
        for d in compute_endpoint_deltas("t1", "p1", old, _ep(200, ["nginx", "php"], "b"))
    }
    assert kinds == {"status_change", "tech_change", "title_change"}


def test_no_change_no_delta():
    old = {"status_code": 200, "tech": ["nginx"], "content_hash": "a"}
    same = Endpoint(
        tenant_id="t1",
        program_id="p1",
        fingerprint="fp",
        url="https://app.customer.com",
        status_code=200,
        tech=["nginx"],
        content_hash="a",
    )
    assert compute_endpoint_deltas("t1", "p1", old, same) == []


async def test_probe_emits_delta_on_status_change():
    mongo = FakeMongo()
    await AssetRepo(mongo.collection("assets")).upsert(
        Asset(
            tenant_id="t1",
            program_id="p1",
            fingerprint=asset_fingerprint("p1", "app.customer.com"),
            hostname="app.customer.com",
            resolved_ips=["45.55.1.1"],
        )
    )

    def probe_returning(status):
        async def probe(hosts, _timeout, *, rate=None):
            return [
                {
                    "url": f"https://{h}",
                    "input": h,
                    "status_code": status,
                    "title": "t",
                    "tech": ["nginx"],
                }
                for h in hosts
            ]

        return probe

    first = await run_probe(
        mongo=mongo,
        engine=ENGINE,
        scope=SCOPE,
        tenant=TENANT,
        program_id="p1",
        timeout=10,
        probe=probe_returning(200),
    )
    assert first["deltas"] == 0  # brand new, no change event

    second = await run_probe(
        mongo=mongo,
        engine=ENGINE,
        scope=SCOPE,
        tenant=TENANT,
        program_id="p1",
        timeout=10,
        probe=probe_returning(403),
    )
    assert second["deltas"] == 1
    deltas = await DeltaRepo(mongo.collection("deltas")).list("t1", "p1")
    assert deltas[0]["kind"] == "status_change"
    assert deltas[0]["before"] == "200" and deltas[0]["after"] == "403"
