"""Phase G: seed script, backup command, scope-feed parsers, metrics, sentry."""

from __future__ import annotations

from fastapi.testclient import TestClient

from api.auth import verify_password
from api.main import create_app
from core.observability import init_sentry
from db.authorizations import AuthorizationRepo
from db.findings import FindingRepo
from db.programs import ProgramRepo
from db.users import UserRepo
from scripts.backup import build_mongodump_cmd
from scripts.seed_dev import DEMO_EMAIL, DEMO_PASSWORD, seed
from scripts.update_scope_feeds import build_feed, parse_aws, parse_cloudflare
from tests.fakes import FakeMongo


# -- seed --------------------------------------------------------------------
async def test_seed_creates_usable_demo_tenant():
    mongo = FakeMongo()
    res = await seed(mongo)

    user = await UserRepo.from_mongo(mongo).get_by_email(DEMO_EMAIL)
    assert user and verify_password(DEMO_PASSWORD, user["password_hash"])

    program = await ProgramRepo.from_mongo(mongo).get(res["tenant_id"], res["program_id"])
    assert program["verified"] is True

    auth = await AuthorizationRepo.from_mongo(mongo).get(res["tenant_id"], res["program_id"])
    assert auth["apex_verified"] is True

    findings = await FindingRepo.from_mongo(mongo).list(res["tenant_id"], res["program_id"])
    assert any(f["severity"] == "critical" for f in findings)


# -- backup ------------------------------------------------------------------
def test_backup_command():
    cmd = build_mongodump_cmd("mongodb://x:27017", "vantari", "/out")
    assert cmd == [
        "mongodump", "--uri=mongodb://x:27017", "--out=/out", "--db=vantari", "--gzip",
    ]
    assert "--gzip" not in build_mongodump_cmd("uri", "db", "/o", gzip=False)


# -- scope feeds -------------------------------------------------------------
def test_parse_aws_splits_cdn_and_cloud():
    payload = {
        "prefixes": [
            {"ip_prefix": "13.32.0.0/15", "service": "CLOUDFRONT"},
            {"ip_prefix": "52.0.0.0/11", "service": "EC2"},
            {"ip_prefix": "1.2.3.0/24", "service": "ROUTE53"},  # ignored
        ]
    }
    out = parse_aws(payload)
    assert out["cdn"] == ["13.32.0.0/15"]
    assert out["cloud_shared"] == ["52.0.0.0/11"]


def test_parse_cloudflare_and_build_feed():
    cf = parse_cloudflare("104.16.0.0/13\n\n172.64.0.0/13\n")
    assert cf == ["104.16.0.0/13", "172.64.0.0/13"]
    feed = build_feed(aws={"cdn": ["13.32.0.0/15"], "cloud_shared": []}, cloudflare=cf)
    names = {p["name"] for p in feed["providers"]}
    assert {"cloudflare", "aws_cloudfront", "aws_cloud"} <= names


# -- metrics + sentry --------------------------------------------------------
def test_http_metrics_are_recorded():
    client = TestClient(create_app())
    client.get("/healthz")
    body = client.get("/metrics").text
    assert "vantari_http_requests_total" in body


def test_sentry_disabled_without_dsn():
    # default settings have no DSN → init is a no-op returning False
    assert init_sentry() is False
