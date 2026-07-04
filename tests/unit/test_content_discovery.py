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
