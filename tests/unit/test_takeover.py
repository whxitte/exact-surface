"""Subdomain-takeover detection: fingerprint match, dangling CNAME, and the pipeline."""

from __future__ import annotations

from core.models import Asset
from core.scope import ProgramScope, ScopeEngine
from core.tenant import TenantContext
from db.assets import AssetRepo
from db.findings import FindingRepo
from modules.takeover import check_host
from pipelines.takeover import run_takeover
from tests.fakes import FakeMongo

ENGINE = ScopeEngine.from_data_file()
SCOPE = ProgramScope(verified_apexes=("acme.com",))
TENANT = TenantContext(tenant_id="t1")


async def test_http_fingerprint_flags_takeover():
    async def fetch(_url):
        return "<html>There isn't a GitHub Pages site here.</html>"

    hit = await check_host("blog.acme.com", ["acme.github.io"], fetch=fetch)
    assert hit and hit["service"] == "GitHub Pages" and hit["signal"] == "http-fingerprint"


async def test_no_fingerprint_no_finding():
    async def fetch(_url):
        return "<html>Welcome, this is a live site.</html>"

    assert await check_host("blog.acme.com", ["acme.github.io"], fetch=fetch) is None


async def test_dangling_cname_flags_nxdomain_service():
    async def fetch(_url):
        return ""

    async def resolve(_target):
        return []  # NXDOMAIN

    hit = await check_host("app.acme.com", ["acme.herokuapp.com"], fetch=fetch, resolve=resolve)
    assert hit and hit["service"] == "Heroku" and hit["signal"] == "nxdomain"


async def test_unknown_cname_target_ignored():
    async def fetch(_url):
        return "anything"

    assert await check_host("x.acme.com", ["x.internal.acme.com"], fetch=fetch) is None


async def test_pipeline_creates_finding_and_flags_asset():
    mongo = FakeMongo()
    repo = AssetRepo.from_mongo(mongo)
    await repo.upsert(
        Asset(
            tenant_id="t1",
            program_id="p1",
            fingerprint="a1",
            hostname="blog.acme.com",
            dns_records={"cname": ["acme.github.io"]},
        )
    )
    await repo.upsert(  # a host with no CNAME — not checked
        Asset(tenant_id="t1", program_id="p1", fingerprint="a2", hostname="www.acme.com")
    )

    async def fetch(_url):
        return "There isn't a GitHub Pages site here."

    res = await run_takeover(
        mongo=mongo,
        engine=ENGINE,
        scope=SCOPE,
        tenant=TENANT,
        program_id="p1",
        timeout=10,
        fetch=fetch,
        resolve=None,
    )
    assert res["checked"] == 1 and res["vulnerable"] == 1 and res["new"] == 1

    findings = await FindingRepo.from_mongo(mongo).list("t1", "p1")
    assert findings[0]["check_id"] == "subdomain-takeover" and findings[0]["severity"] == "high"
    asset = await repo.get("t1", "a1")
    assert asset["takeover_risk"] == "GitHub Pages"


async def test_s3_behind_cloudfront_detected_by_body():
    # The real miss: CNAME is CloudFront (unknown service) but the body is S3's
    # NoSuchBucket — must still be flagged via the body scan.
    body = (
        "<html><head><title>404 Not Found</title></head><body>"
        "<li>Code: NoSuchBucket</li></body></html>"
    )

    async def fetch(_url):
        return body

    hit = await check_host(
        "dev-quipolite.quipohealth.com",
        ["d123.cloudfront.net"],  # CloudFront CNAME — not itself a known service
        fetch=fetch,
    )
    assert hit and hit["service"] == "AWS/S3" and hit["signal"] == "http-fingerprint"


async def test_pipeline_checks_resolving_host_without_cname():
    mongo = FakeMongo()
    repo = AssetRepo.from_mongo(mongo)
    await repo.upsert(
        Asset(
            tenant_id="t1",
            program_id="p1",
            fingerprint="s3",
            hostname="dev.acme.com",
            resolved_ips=["13.1.1.1"],  # resolves (to CloudFront) but no telltale CNAME
        )
    )

    async def fetch(_url):
        return "<li>Code: NoSuchBucket</li>"

    res = await run_takeover(
        mongo=mongo,
        engine=ENGINE,
        scope=SCOPE,
        tenant=TENANT,
        program_id="p1",
        timeout=10,
        fetch=fetch,
        resolve=None,
    )
    assert res["checked"] == 1 and res["vulnerable"] == 1
    asset = await repo.get("t1", "s3")
    assert asset["takeover_risk"] == "AWS/S3"


async def test_pipeline_skips_when_no_cnames():
    mongo = FakeMongo()
    await AssetRepo.from_mongo(mongo).upsert(
        Asset(tenant_id="t1", program_id="p1", fingerprint="a1", hostname="www.acme.com")
    )
    res = await run_takeover(
        mongo=mongo, engine=ENGINE, scope=SCOPE, tenant=TENANT, program_id="p1", timeout=10
    )
    assert res.get("skipped") and res["checked"] == 0
