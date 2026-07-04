"""Report generation: context, renderers, escaping/masking, pipeline formats."""

from __future__ import annotations

import pytest

from core.models import Asset, CveMatch, ExposedSecret, Finding, Program
from core.severity import Severity
from core.tenant import TenantContext
from db.assets import AssetRepo
from db.cves import CveMatchRepo
from db.findings import FindingRepo
from db.programs import ProgramRepo
from db.secrets import SecretRepo
from modules.reporting.context import build_report_context
from modules.reporting.executive_summary import render_executive_summary
from modules.reporting.hackerone_report import render_hackerone
from modules.reporting.html_report import render_html
from modules.reporting.pdf_report import render_pdf
from pipelines.report import generate_report
from tests.fakes import FakeMongo

TENANT = TenantContext("t1", "u1")
AWS_MASKED = "AKIA••••••••LE"


def _ctx():
    return build_report_context(
        program="acme.com",
        assets=[
            {
                "hostname": "app.acme.com",
                "fingerprint": "a1",
                "resolved_ips": ["45.55.1.1"],
                "is_ephemeral": False,
            }
        ],
        endpoints=[{"url": "https://app.acme.com"}],
        findings=[
            {
                "name": "minor",
                "severity": "low",
                "location": "https://app.acme.com/x",
                "module": "nuclei",
            },
            {
                "name": "Exposed .env",
                "severity": "critical",
                "location": "https://app.acme.com/.env",
                "module": "nuclei",
                "check_id": "exposed-env",
            },
        ],
        secrets=[
            {
                "kind": "aws_access_key",
                "masked": AWS_MASKED,
                "source_locator": "https://app.acme.com/app.js",
            }
        ],
        leaks=[],
        cve_matches=[
            {"cve_id": "CVE-1", "confidence": "low", "severity": "medium"},
            {
                "cve_id": "CVE-2",
                "on_kev": True,
                "confidence": "high",
                "severity": "critical",
                "asset_fingerprint": "a1",
            },
        ],
        ports=[{"ip": "45.55.1.1", "port": 22}],
    )


# -- context -----------------------------------------------------------------
def test_context_sorts_and_filters():
    ctx = _ctx()
    assert ctx.findings[0]["severity"] == "critical"  # sorted, critical first
    assert ctx.severity_counts["critical"] == 1 and ctx.severity_counts["low"] == 1
    assert ctx.counts["cve_matches"] == 1  # only the high/KEV one is kept
    assert ctx.issues and ctx.issues[0].host == "app.acme.com"


# -- renderers ---------------------------------------------------------------
def test_hackerone_has_sections_and_impact():
    md = render_hackerone(_ctx())
    assert "## [CRITICAL] Exposed .env" in md
    assert "### Steps to Reproduce" in md and "### Impact" in md
    assert "curl -i https://app.acme.com/.env" in md


def test_executive_summary_flags_posture_and_rotation():
    md = render_executive_summary(_ctx())
    assert "critical exposure present" in md
    assert "immediate rotation" in md.lower()
    assert "app.acme.com" in md  # top risk listed


def test_html_escapes_and_masks():
    ctx = build_report_context(
        program="acme.com",
        assets=[],
        endpoints=[],
        findings=[
            {
                "name": "<script>alert(1)</script>",
                "severity": "high",
                "location": "https://x",
                "module": "nuclei",
            }
        ],
        secrets=[{"kind": "aws", "masked": AWS_MASKED, "source_locator": "u"}],
        leaks=[],
        cve_matches=[],
        ports=[],
    )
    html = render_html(ctx)
    assert "<script>alert(1)</script>" not in html  # escaped
    assert "&lt;script&gt;" in html
    assert AWS_MASKED in html


def test_pdf_uses_injected_renderer():
    called = {}

    def fake_renderer(html: str) -> bytes:
        called["html"] = html
        return b"%PDF-1.4 fake"

    out = render_pdf("<html></html>", renderer=fake_renderer)
    assert out == b"%PDF-1.4 fake" and called["html"] == "<html></html>"


# -- pipeline ----------------------------------------------------------------
async def _seed(mongo):
    await ProgramRepo.from_mongo(mongo).save(
        Program(tenant_id="t1", program_id="p1", apex_domain="acme.com", verified=True)
    )
    await AssetRepo(mongo.collection("assets")).upsert(
        Asset(
            tenant_id="t1",
            program_id="p1",
            fingerprint="a1",
            hostname="app.acme.com",
            resolved_ips=["45.55.1.1"],
        )
    )
    await FindingRepo(mongo.collection("findings")).upsert(
        Finding(
            tenant_id="t1",
            program_id="p1",
            fingerprint="f1",
            check_id="exposed-env",
            module="nuclei",
            location="https://app.acme.com/.env",
            name="Exposed .env",
            severity=Severity.CRITICAL,
        )
    )
    await SecretRepo(mongo.collection("secrets")).upsert(
        ExposedSecret(
            tenant_id="t1",
            program_id="p1",
            fingerprint="s1",
            kind="aws_access_key",
            masked=AWS_MASKED,
            value_hash="h",
            source_locator="https://app.acme.com/app.js",
            severity=Severity.HIGH,
        )
    )
    await CveMatchRepo(mongo.collection("cve_matches")).upsert(
        CveMatch(
            tenant_id="t1",
            program_id="p1",
            fingerprint="c1",
            cve_id="CVE-2",
            cpe="cpe",
            asset_fingerprint="a1",
            on_kev=True,
            confidence="high",
            severity=Severity.CRITICAL,
        )
    )


async def test_generate_report_all_text_formats():
    mongo = FakeMongo()
    await _seed(mongo)
    for fmt, needle in [
        ("html", "Vantari Attack-Surface Report"),
        ("hackerone", "## [CRITICAL] Exposed .env"),
        ("executive", "Executive Summary"),
    ]:
        report = await generate_report(mongo=mongo, tenant=TENANT, program_id="p1", fmt=fmt)
        assert needle in report.body
        assert "AKIAIOSFODNN7EXAMPLE" not in report.body  # plaintext never in a report (§9c)
    # the masked value appears in the HTML secret table
    html = await generate_report(mongo=mongo, tenant=TENANT, program_id="p1", fmt="html")
    assert AWS_MASKED in html.body


async def test_generate_report_pdf_with_injected_renderer():
    mongo = FakeMongo()
    await _seed(mongo)
    report = await generate_report(
        mongo=mongo,
        tenant=TENANT,
        program_id="p1",
        fmt="pdf",
        pdf_renderer=lambda html: b"%PDF fake",
    )
    assert report.body == b"%PDF fake" and report.content_type == "application/pdf"


async def test_generate_report_unknown_format():
    mongo = FakeMongo()
    await _seed(mongo)
    with pytest.raises(ValueError, match="unknown report format"):
        await generate_report(mongo=mongo, tenant=TENANT, program_id="p1", fmt="xlsx")
