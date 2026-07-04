"""Port scan: naabu/nmap parsing + the §9b 'dedicated IPs only' scope boundary."""

from __future__ import annotations

from core.hashing import asset_fingerprint
from core.models import Asset
from core.scope import ProgramScope, ScopeEngine
from core.tenant import TenantContext
from db.assets import AssetRepo
from db.ports import PortRepo
from modules.ports.naabu import scan_ports
from modules.ports.nmap import service_scan
from pipelines.port_scan import run_port_scan
from tests.fakes import FakeMongo

ENGINE = ScopeEngine.from_data_file()
TENANT = TenantContext("t1", "u1")
SCOPE = ProgramScope(
    verified_apexes=("customer.com",), authorized_dedicated_cidrs=("45.55.0.0/16",)
)


async def test_naabu_parses_open_ports():
    rows = [
        {"ip": "45.55.1.1", "host": "app.customer.com", "port": 443, "protocol": "tcp"},
        {"ip": "45.55.1.1", "port": 80},
        {"garbage": True},
    ]

    async def runner(binary, args, *, timeout, stdin=None):
        return rows

    out = await scan_ports(["app.customer.com"], 10, runner=runner)
    assert {p["port"] for p in out} == {443, 80}


async def test_nmap_parses_greppable_service_version():
    grep = (
        "# Nmap\n"
        "Host: 45.55.1.1 ()\tPorts: 22/open/tcp//ssh//OpenSSH 8.2p1/, "
        "443/open/tcp//https//nginx 1.18.0/\n"
    )

    async def runner(binary, args, *, timeout, stdin=None):
        return grep

    out = await service_scan("45.55.1.1", [22, 443], 10, runner=runner)
    by_port = {s["port"]: s for s in out}
    assert by_port[22]["service"] == "ssh" and "OpenSSH" in by_port[22]["version"]
    assert by_port[443]["service"] == "https"


async def test_port_scan_only_scans_dedicated_hosts():
    mongo = FakeMongo()
    ar = AssetRepo(mongo.collection("assets"))
    await ar.upsert(
        Asset(
            tenant_id="t1",
            program_id="p1",
            fingerprint=asset_fingerprint("p1", "app.customer.com"),
            hostname="app.customer.com",
            resolved_ips=["45.55.1.1"],
        )
    )  # dedicated
    await ar.upsert(
        Asset(
            tenant_id="t1",
            program_id="p1",
            fingerprint=asset_fingerprint("p1", "www.customer.com"),
            hostname="www.customer.com",
            resolved_ips=["104.16.5.5"],
        )
    )  # cloudflare

    scanned_hosts = []

    async def fake_naabu(hosts, _timeout):
        scanned_hosts.extend(hosts)
        return [{"ip": "45.55.1.1", "host": "app.customer.com", "port": 443, "protocol": "tcp"}]

    res = await run_port_scan(
        mongo=mongo,
        engine=ENGINE,
        scope=SCOPE,
        tenant=TENANT,
        program_id="p1",
        timeout=10,
        naabu=fake_naabu,
    )

    # the CDN host must NEVER be handed to the port scanner (§9b)
    assert scanned_hosts == ["app.customer.com"]
    assert res["ports"] == 1 and res["new"] == 1
    assert await PortRepo(mongo.collection("ports")).count("t1") == 1


async def test_port_scan_nmap_enrichment():
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

    async def fake_naabu(hosts, _timeout):
        return [{"ip": "45.55.1.1", "host": "app.customer.com", "port": 22, "protocol": "tcp"}]

    async def fake_nmap(ip, ports, _timeout):
        return [
            {
                "port": 22,
                "protocol": "tcp",
                "state": "open",
                "service": "ssh",
                "version": "OpenSSH 8.2",
            }
        ]

    await run_port_scan(
        mongo=mongo,
        engine=ENGINE,
        scope=SCOPE,
        tenant=TENANT,
        program_id="p1",
        timeout=10,
        naabu=fake_naabu,
        nmap=fake_nmap,
    )
    ports = await PortRepo(mongo.collection("ports")).list("t1", "p1")
    assert ports[0]["service"] == "ssh" and ports[0]["version"] == "OpenSSH 8.2"
