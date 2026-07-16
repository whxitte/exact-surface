"""Pipeline-level scope enforcement — "a listing ≠ authorization" (§9b, §8).

Unit tests prove the scope *engine* denies the right things; this proves a real
*pipeline* actually consults it before persisting anything. We drive
``run_uncover`` (which reaches Shodan/Censys and could otherwise ingest whatever
those return) with a stubbed search returning a mix of in-scope and out-of-scope
results, against a real ``ProgramScope`` + in-memory Mongo. Only the owned
hostname and the IP inside the authorized dedicated CIDR may be persisted; a
third party's hostname and an unauthorized IP must be dropped — no asset, no
port, no network call to reach them.
"""

from __future__ import annotations

import asyncio

from core.scope import ProgramScope, ScopeEngine
from core.tenant import TenantContext
from db.assets import AssetRepo
from db.ports import PortRepo
from pipelines.uncover import run_uncover
from tests.fakes import FakeMongo

ENGINE = ScopeEngine.from_data_file()
SCOPE = ProgramScope(
    verified_apexes=("customer.com",),
    authorized_dedicated_cidrs=("45.55.0.0/16",),
)


def _run(coro):
    return asyncio.run(coro)


async def _fake_search(_apex: str):
    # A mix the engine must sort out:
    return [
        {"host": "api.customer.com", "ip": "13.1.1.1", "port": 443},  # owned host, CDN ip → asset
        {"host": "45.55.1.9", "ip": "45.55.1.9", "port": 6379},  # authorized dedicated ip → port
        {"host": "8.8.8.8", "ip": "8.8.8.8", "port": 53},  # unowned ip, not a host → dropped
        {"host": "evil-lookalike.com", "ip": "1.2.3.4", "port": 443},  # third party → dropped
    ]


def test_uncover_persists_only_in_scope_results():
    fake = FakeMongo()
    tenant = TenantContext(tenant_id="t_demo")
    out = _run(
        run_uncover(
            mongo=fake,
            engine=ENGINE,
            scope=SCOPE,
            tenant=tenant,
            program_id="prog_x",
            apex="customer.com",
            timeout=5,
            search=_fake_search,
        )
    )

    # 4 indexed, 1 owned host → asset, 1 authorized ip → port, 2 dropped.
    assert out["found"] == 4
    assert out["new_assets"] == 1
    assert out["new_ports"] == 1
    assert out["out_of_scope"] == 2

    assets = _run(AssetRepo.from_mongo(fake).list("t_demo", "prog_x", limit=100))
    hostnames = {a["hostname"] for a in assets}
    assert hostnames == {"api.customer.com"}
    assert "evil-lookalike.com" not in hostnames  # third-party host never persisted

    ports = _run(PortRepo.from_mongo(fake).list("t_demo", "prog_x", limit=100))
    port_ips = {p["ip"] for p in ports}
    assert port_ips == {"45.55.1.9"}
    assert "8.8.8.8" not in port_ips  # unauthorized ip never persisted


def test_uncover_with_empty_scope_persists_nothing():
    """A program with no verified apex and no authorized CIDR ingests nothing —
    the default-deny posture holds end-to-end."""
    fake = FakeMongo()
    empty_scope = ProgramScope(verified_apexes=("customer.com",))  # no dedicated CIDRs
    out = _run(
        run_uncover(
            mongo=fake,
            engine=ENGINE,
            scope=empty_scope,
            tenant=TenantContext(tenant_id="t_demo"),
            program_id="prog_y",
            apex="customer.com",
            timeout=5,
            search=lambda _apex: _only_ips(),
        )
    )
    assert out["new_assets"] == 0 and out["new_ports"] == 0
    assert out["out_of_scope"] == out["found"]


async def _only_ips():
    return [
        {"host": "45.55.1.9", "ip": "45.55.1.9", "port": 6379},  # ip authorized nowhere now
        {"host": "8.8.8.8", "ip": "8.8.8.8", "port": 53},
    ]
