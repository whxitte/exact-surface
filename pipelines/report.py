"""Report pipeline (§module 30-33) — gather program data → render a format."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from core.tenant import TenantContext
from db.assets import AssetRepo
from db.cves import CveMatchRepo
from db.endpoints import EndpointRepo
from db.findings import FindingRepo
from db.leaks import LeakRepo
from db.ports import PortRepo
from db.programs import ProgramRepo
from db.secrets import SecretRepo
from modules.reporting.context import build_report_context
from modules.reporting.executive_summary import render_executive_summary
from modules.reporting.hackerone_report import render_hackerone
from modules.reporting.html_report import render_html
from modules.reporting.pdf_report import render_pdf

REPORT_FORMATS = ("html", "hackerone", "executive", "pdf")


@dataclass
class Report:
    content_type: str
    filename: str
    body: str | bytes


async def _gather(mongo: Any, tenant_id: str, program_id: str) -> dict:
    async def _all(repo_cls) -> list[dict]:
        return await repo_cls.from_mongo(mongo).list(tenant_id, program_id, limit=100_000)

    return {
        "assets": await _all(AssetRepo),
        "endpoints": await _all(EndpointRepo),
        "findings": await _all(FindingRepo),
        "secrets": await _all(SecretRepo),
        "leaks": await _all(LeakRepo),
        "cve_matches": await _all(CveMatchRepo),
        "ports": await _all(PortRepo),
    }


async def generate_report(
    *,
    mongo: Any,
    tenant: TenantContext,
    program_id: str,
    fmt: str,
    pdf_renderer=None,
) -> Report:
    if fmt not in REPORT_FORMATS:
        raise ValueError(f"unknown report format: {fmt}")

    program = await ProgramRepo.from_mongo(mongo).get(tenant.tenant_id, program_id)
    apex = program["apex_domain"] if program else program_id
    ctx = build_report_context(program=apex, **await _gather(mongo, tenant.tenant_id, program_id))
    stem = apex.replace(".", "-")

    if fmt == "html":
        return Report("text/html; charset=utf-8", f"{stem}-report.html", render_html(ctx))
    if fmt == "hackerone":
        return Report("text/markdown; charset=utf-8", f"{stem}-hackerone.md", render_hackerone(ctx))
    if fmt == "executive":
        return Report(
            "text/markdown; charset=utf-8", f"{stem}-executive.md", render_executive_summary(ctx)
        )
    # pdf
    pdf = render_pdf(render_html(ctx), renderer=pdf_renderer)
    return Report("application/pdf", f"{stem}-report.pdf", pdf)
