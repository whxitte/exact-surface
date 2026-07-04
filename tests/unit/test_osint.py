"""OSINT modules: GitHub leaks, ASN mapper, cloud buckets."""

from __future__ import annotations

import json

from core.tenant import TenantContext
from db.leaks import LeakRepo
from modules.osint.asn_mapper import map_domain
from modules.osint.cloud_buckets import enumerate_buckets, permutations
from modules.osint.github import search_leaks
from pipelines.github_osint import run_github_leak_scan
from tests.fakes import FakeMongo

TENANT = TenantContext("t1", "u1")
AWS = "AKIAIOSFODNN7EXAMPLE"


# -- github ------------------------------------------------------------------
async def test_github_search_leaks_detects_secret():
    async def search(_query):
        return [
            {
                "repo": "acme/config",
                "path": ".env",
                "html_url": "https://github.com/acme/config/.env",
                "content": f"AWS_KEY={AWS}",
            }
        ]

    hits = await search_leaks("customer.com", search=search)
    assert (
        len(hits) == 1 and hits[0]["kind"] == "aws_access_key" and hits[0]["repo"] == "acme/config"
    )


async def test_github_pipeline_stores_masked_leak():
    mongo = FakeMongo()

    async def search(_q):
        return [
            {
                "repo": "acme/x",
                "path": "cfg",
                "html_url": "https://github.com/acme/x",
                "content": AWS,
            }
        ]

    res = await run_github_leak_scan(
        mongo=mongo,
        tenant=TENANT,
        program_id="p1",
        domain="customer.com",
        hmac_key=b"k",
        search=search,
    )
    assert res["new"] == 1
    doc = (await LeakRepo(mongo.collection("leaks")).list("t1", "p1"))[0]
    assert doc["masked"].startswith("AKIA") and AWS not in json.dumps(doc, default=str)


# -- asn ---------------------------------------------------------------------
async def test_asn_map_domain_collects_ranges():
    async def runner(binary, args, *, timeout, stdin=None):
        return [{"as_range": ["45.55.0.0/16", "104.16.0.0/13"]}, {"as_range": ["45.55.0.0/16"]}]

    assert await map_domain("customer.com", 10, runner=runner) == ["104.16.0.0/13", "45.55.0.0/16"]


# -- cloud buckets -----------------------------------------------------------
def test_bucket_permutations_cover_providers():
    perms = permutations("customer.com")
    providers = {p for p, _, _ in perms}
    assert providers == {"s3", "gcs", "azure"}
    # domain label only, not the TLD
    assert all("customer" in name for _, name, _ in perms)


async def test_enumerate_buckets_flags_existing_only():
    async def checker(url):
        return 200 if url.endswith("customer.s3.amazonaws.com") else 404

    found = await enumerate_buckets("customer", checker=checker)
    assert len(found) == 1
    assert found[0]["provider"] == "s3" and found[0]["public"] is True
