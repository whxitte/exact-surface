"""Content discovery: tech-aware wordlist selection + dedicated-only scope."""

from __future__ import annotations

import pytest

from core.hashing import asset_fingerprint, endpoint_fingerprint
from core.models import Asset, Endpoint
from core.scope import ProgramScope, ScopeEngine
from core.tenant import TenantContext
from db.assets import AssetRepo
from db.endpoints import EndpointRepo
from modules.content_discovery.feroxbuster import discover
from modules.content_discovery.wordlist_selector import DEFAULT_WORDLIST, select_wordlist
from pipelines.content_discovery import run_content_discovery
from tests.fakes import FakeMongo

ENGINE = ScopeEngine.from_data_file()
TENANT = TenantContext("t1", "u1")
SCOPE = ProgramScope(
    verified_apexes=("customer.com",), authorized_dedicated_cidrs=("45.55.0.0/16",)
)


@pytest.mark.parametrize(
    "tech,expected",
    [
        (["WordPress 5.4"], "wp-common.txt"),
        (["nginx"], "nginx.txt"),
        (["Apache Tomcat"], "tomcat.txt"),
        (["React", "Cloudflare"], DEFAULT_WORDLIST),
        ([], DEFAULT_WORDLIST),
    ],
)
def test_select_wordlist(tech, expected):
    assert select_wordlist(tech) == expected


async def test_feroxbuster_parses_responses():
    rows = [
        {"type": "response", "url": "https://a/admin", "status": 200, "content_length": 10},
        {"type": "statistics"},  # ignored
        {"type": "response", "url": "https://a/login", "status": 401},
    ]

    async def runner(binary, args, *, timeout, stdin=None):
        return rows

    out = await discover("https://a", "wp-common.txt", 10, runner=runner)
    assert {r["url"] for r in out} == {"https://a/admin", "https://a/login"}


async def test_content_discovery_dedicated_only_and_tech_aware():
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
    )  # CDN
    await EndpointRepo(mongo.collection("endpoints")).upsert(
        Endpoint(
            tenant_id="t1",
            program_id="p1",
            fingerprint=endpoint_fingerprint("p1", "GET", "https://app.customer.com"),
            url="https://app.customer.com",
            tech=["WordPress 5.4"],
        )
    )

    calls = []

    async def fake_discover(url, wordlist, _timeout):
        calls.append({"url": url, "wordlist": wordlist})
        return [{"url": f"{url}/wp-admin", "status": 200}]

    res = await run_content_discovery(
        mongo=mongo,
        engine=ENGINE,
        scope=SCOPE,
        tenant=TENANT,
        program_id="p1",
        timeout=10,
        discover=fake_discover,
    )

    # only the dedicated host was fuzzed, and with the WordPress wordlist
    assert len(calls) == 1
    assert calls[0]["url"] == "https://app.customer.com"
    assert calls[0]["wordlist"] == "wp-common.txt"
    assert res["new"] == 1


async def test_uses_probed_scheme_and_skips_unprobed_hosts():
    # feroxbuster aborts if handed https:// for an http-only host, and can't discover on
    # a host with no web server — so we fuzz probed-alive hosts at their working URL only.
    mongo = FakeMongo()
    ar = AssetRepo(mongo.collection("assets"))
    er = EndpointRepo(mongo.collection("endpoints"))
    for host, ip in [("http-only.customer.com", "45.55.1.2"), ("dead.customer.com", "45.55.1.3")]:
        await ar.upsert(
            Asset(
                tenant_id="t1",
                program_id="p1",
                fingerprint=asset_fingerprint("p1", host),
                hostname=host,
                resolved_ips=[ip],
            )
        )
    # only the http-only host was probed alive (over http); 'dead' has no endpoint
    await er.upsert(
        Endpoint(
            tenant_id="t1",
            program_id="p1",
            fingerprint=endpoint_fingerprint("p1", "GET", "http://http-only.customer.com"),
            url="http://http-only.customer.com",
        )
    )

    calls: list[str] = []

    async def fake_discover(url, _wordlist, _timeout):
        calls.append(url)
        return []

    res = await run_content_discovery(
        mongo=mongo,
        engine=ENGINE,
        scope=SCOPE,
        tenant=TENANT,
        program_id="p1",
        timeout=10,
        discover=fake_discover,
    )
    assert calls == ["http://http-only.customer.com"]  # http scheme kept; dead host skipped
    assert res["hosts"] == 1


async def test_ffuf_fallback_when_feroxbuster_cant_connect(monkeypatch):
    # feroxbuster's client can't reach a host httpx already probed alive → retry with ffuf.
    from modules.content_discovery.feroxbuster import TargetUnreachable

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
    await EndpointRepo(mongo.collection("endpoints")).upsert(
        Endpoint(
            tenant_id="t1",
            program_id="p1",
            fingerprint=endpoint_fingerprint("p1", "GET", "https://app.customer.com"),
            url="https://app.customer.com",
        )
    )

    async def fake_discover(_url, _wordlist, _timeout):
        raise TargetUnreachable("Could not connect to any target provided")

    ffuf_calls: list[str] = []

    async def fake_fuzz(url, _wordlist, _timeout):
        ffuf_calls.append(url)
        return [{"url": "https://app.customer.com/admin", "status": 200}]

    monkeypatch.setattr("modules.content_discovery.ffuf.fuzz", fake_fuzz)
    res = await run_content_discovery(
        mongo=mongo,
        engine=ENGINE,
        scope=SCOPE,
        tenant=TENANT,
        program_id="p1",
        timeout=10,
        discover=fake_discover,
    )
    assert ffuf_calls == ["https://app.customer.com/FUZZ"] and res["new"] == 1


async def test_content_discovery_fallback_to_ffuf(monkeypatch):
    from core.errors import ToolNotFound

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
    await EndpointRepo(mongo.collection("endpoints")).upsert(
        Endpoint(
            tenant_id="t1",
            program_id="p1",
            fingerprint=endpoint_fingerprint("p1", "GET", "https://app.customer.com"),
            url="https://app.customer.com",  # probed alive → eligible for content discovery
        )
    )

    async def fake_discover(url, wordlist, _timeout):
        raise ToolNotFound("feroxbuster")

    ffuf_calls = []

    async def fake_fuzz(url, wordlist, _timeout):
        ffuf_calls.append({"url": url, "wordlist": wordlist})
        return [{"url": "https://app.customer.com/admin", "status": 200}]

    monkeypatch.setattr("modules.content_discovery.ffuf.fuzz", fake_fuzz)

    res = await run_content_discovery(
        mongo=mongo,
        engine=ENGINE,
        scope=SCOPE,
        tenant=TENANT,
        program_id="p1",
        timeout=10,
        discover=fake_discover,
    )

    assert len(ffuf_calls) == 1
    assert ffuf_calls[0]["url"] == "https://app.customer.com/FUZZ"
    assert res["new"] == 1
