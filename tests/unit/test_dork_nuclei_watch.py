"""Dorking pipeline + nuclei-template watch."""

from __future__ import annotations

from core.severity import Severity
from core.tenant import TenantContext
from db.findings import FindingRepo
from modules.dorking.templates import category_severity, render
from modules.intelligence.nuclei_watch import new_template_ids, relevant_templates
from pipelines.dork import run_dork
from tests.fakes import FakeMongo

TENANT = TenantContext("t1", "u1")


# -- dorking -----------------------------------------------------------------
def test_render_fills_domain_and_covers_categories():
    dorks = render("customer.com")
    assert all("customer.com" in d["query"] for d in dorks)
    assert {d["category"] for d in dorks} >= {"exposed_files", "secrets", "auth", "config"}


def test_category_severity():
    assert category_severity("secrets") == Severity.CRITICAL
    assert category_severity("exposed_files") == Severity.HIGH
    assert category_severity("unknown") == Severity.INFO


async def test_run_dork_stores_findings_and_dedupes():
    mongo = FakeMongo()

    async def search(query):
        # one indexed hit for env-file dorks, deduped across queries by link
        if "ext:env" in query:
            return [{"title": "leaked env", "link": "https://customer.com/.env"}]
        return []

    res = await run_dork(
        mongo=mongo, tenant=TENANT, program_id="p1", domain="customer.com", search=search
    )
    assert res["new"] == 1
    docs = await FindingRepo(mongo.collection("findings")).list("t1", "p1")
    assert docs[0]["module"] == "dork" and docs[0]["severity"] == "high"


# -- nuclei watch ------------------------------------------------------------
def test_new_template_ids():
    assert new_template_ids({"a", "b"}, {"a", "b", "c"}) == {"c"}


def test_relevant_templates_match_by_product_or_tag():
    templates = [
        {"id": "wp-x", "product": "wordpress", "tags": ["wordpress", "cve"]},
        {"id": "nginx-y", "product": "nginx", "tags": ["nginx"]},
        {"id": "misc-z", "product": "", "tags": ["misc"]},
    ]
    matched = relevant_templates(templates, {"wordpress"})
    assert {t["id"] for t in matched} == {"wp-x"}
