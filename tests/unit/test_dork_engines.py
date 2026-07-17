"""Dork search engines (module 20) — Brave, SerpAPI, and engine resolution.

All three engines must return the same ``{title, link, snippet}`` shape so the
dork pipeline can swap between them, and an unconfigured engine must return
nothing rather than raise.
"""

from __future__ import annotations

from core.tenant import TenantContext
from db.integrations import IntegrationSecretRepo
from modules.dorking.brave import search as brave_search
from modules.dorking.serpapi import search as serp_search
from pipelines.dork import _resolve_engine, run_dork
from tests.fakes import FakeMongo

TENANT = TenantContext(tenant_id="t1")


# -- brave -------------------------------------------------------------------
async def test_brave_maps_results_to_the_common_shape():
    captured: dict = {}

    async def fake_fetch(url, headers=None):
        captured["url"], captured["headers"] = url, headers
        return {
            "web": {
                "results": [
                    {"title": "T", "url": "https://x/1", "description": "D"},
                    {"title": "no-url", "description": "skipped"},  # dropped
                ]
            }
        }

    out = await brave_search("site:acme.com ext:sql", key="bk", fetch=fake_fetch)
    assert out == [{"title": "T", "link": "https://x/1", "snippet": "D"}]
    # authenticates by header, and url-encodes the dork
    assert captured["headers"]["X-Subscription-Token"] == "bk"
    assert "site%3Aacme.com" in captured["url"]


async def test_brave_without_key_returns_nothing():
    async def boom(*_a, **_k):
        raise AssertionError("must not call the API without a key")

    assert await brave_search("q", key=None, fetch=boom) == []


async def test_brave_tolerates_an_empty_payload():
    async def fake_fetch(_url, _headers=None):
        return {}

    assert await brave_search("q", key="bk", fetch=fake_fetch) == []


# -- serpapi -----------------------------------------------------------------
async def test_serpapi_maps_results_to_the_common_shape():
    captured: dict = {}

    async def fake_fetch(url):
        captured["url"] = url
        return {
            "organic_results": [
                {"title": "T", "link": "https://x/1", "snippet": "S"},
                {"title": "no-link"},  # dropped
            ]
        }

    out = await serp_search("site:acme.com", key="sk", fetch=fake_fetch)
    assert out == [{"title": "T", "link": "https://x/1", "snippet": "S"}]
    assert "api_key=sk" in captured["url"]


async def test_serpapi_without_key_returns_nothing():
    async def boom(_url):
        raise AssertionError("must not call the API without a key")

    assert await serp_search("q", key=None, fetch=boom) == []


# -- engine resolution -------------------------------------------------------
async def test_no_keys_resolves_to_nothing():
    search, name = await _resolve_engine(FakeMongo(), "t1")
    assert search is None and name == ""


async def test_google_wins_when_configured():
    mongo = FakeMongo()
    await IntegrationSecretRepo.from_mongo(mongo).set("t1", "google_cse_key", "gk")
    await IntegrationSecretRepo.from_mongo(mongo).set("t1", "google_cse_cx", "cx")
    await IntegrationSecretRepo.from_mongo(mongo).set("t1", "brave_api_key", "bk")
    _search, name = await _resolve_engine(mongo, "t1")
    assert name == "google_cse"


async def test_brave_used_when_google_is_incomplete():
    """A CSE key without its cx is unusable — fall through, don't half-configure."""
    mongo = FakeMongo()
    await IntegrationSecretRepo.from_mongo(mongo).set("t1", "google_cse_key", "gk")  # no cx
    await IntegrationSecretRepo.from_mongo(mongo).set("t1", "brave_api_key", "bk")
    _search, name = await _resolve_engine(mongo, "t1")
    assert name == "brave"


async def test_serpapi_is_the_last_resort():
    """It is metered per search, so it must not pre-empt the cheaper engines."""
    mongo = FakeMongo()
    await IntegrationSecretRepo.from_mongo(mongo).set("t1", "serpapi_key", "sk")
    _search, name = await _resolve_engine(mongo, "t1")
    assert name == "serpapi"

    await IntegrationSecretRepo.from_mongo(mongo).set("t1", "brave_api_key", "bk")
    _search, name = await _resolve_engine(mongo, "t1")
    assert name == "brave"  # brave now pre-empts serpapi


async def test_dork_skip_note_lists_every_supported_engine():
    res = await run_dork(mongo=FakeMongo(), tenant=TENANT, program_id="p1", domain="acme.com")
    assert res["skipped"] is True
    for engine in ("Google CSE", "Brave", "SerpAPI"):
        assert engine in res["note"]
