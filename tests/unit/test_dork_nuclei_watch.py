"""Dorking pipeline + nuclei-template watch."""

from __future__ import annotations

import pytest

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
            return [
                {
                    "title": "leaked env",
                    "link": "https://customer.com/.env",
                    "snippet": "DB_PASSWORD=…",
                }
            ]
        return []

    res = await run_dork(
        mongo=mongo, tenant=TENANT, program_id="p1", domain="customer.com", search=search
    )
    assert res["new"] == 1
    docs = await FindingRepo(mongo.collection("findings")).list("t1", "p1")
    f = docs[0]
    assert f["module"] == "dork" and f["severity"] == "high"
    # Full transparency: the exact dork query + snippet + a reproduction are all on
    # the finding, nothing hidden (the user must see WHY it was flagged).
    assert "ext:env" in f["locator"]  # the exact dork
    assert "DB_PASSWORD" in f["description"]  # the indexed snippet
    assert f["raw"]["dork_query"] == f["locator"]
    # ext:env is structural: the URL itself is the evidence, no fetch needed, and the
    # reproduction is the page, not a search.
    assert f["raw"]["verified"] is True
    assert f["reproduction"].startswith("curl -sk 'https://customer.com/.env'")


# -- dork verification: a search hit is a lead, not a finding ----------------
TOS_PROSE = (
    "<html><title>Terms of Use</title><body>The service will provide mechanisms that (a) allow "
    "for user password management; (b) transmit passwords in a secure format</body></html>"
)
CREDENTIAL_QUERY = 'site:customer.com "password=" OR "passwd=" OR "pwd="'


async def _search_credentials(query):
    if query == CREDENTIAL_QUERY:
        return [
            {
                "title": "Terms of Use",
                "link": "https://customer.com/terms",
                "snippet": "…password…",
            },
            {"title": "config", "link": "https://customer.com/.git/config", "snippet": "…"},
        ]
    return []


@pytest.mark.asyncio
async def test_a_prose_page_that_merely_mentions_passwords_is_not_a_critical():
    """The real case: two 'critical' findings on a terms-of-service page, because the
    engine matched the word 'password' for the query "password=". The page is
    fetched, the literal token is absent, and the hit is dropped — not downgraded."""
    mongo = FakeMongo()

    async def fetch(url):
        return TOS_PROSE if url.endswith("/terms") else "db password=hunter2\nhost=db.internal"

    res = await run_dork(
        mongo=mongo,
        tenant=TENANT,
        program_id="p1",
        domain="customer.com",
        search=_search_credentials,
        fetch=fetch,
    )
    docs = await FindingRepo(mongo.collection("findings")).list("t1", "p1")
    assert res["dropped_unverified"] == 1
    assert [d["location"] for d in docs] == ["https://customer.com/.git/config"]
    f = docs[0]
    assert f["severity"] == "critical" and f["raw"]["verified"] is True
    assert f["raw"]["matched"] == "password=" and "hunter2" in f["description"]
    assert (
        f["reproduction"] == "curl -sk 'https://customer.com/.git/config' | grep -i -- 'password='"
    )


@pytest.mark.asyncio
async def test_a_hit_that_cannot_be_fetched_is_kept_low_and_labelled():
    """Unknown is not clean: a blocked or rate-limited page must not be mistaken for a
    page with nothing on it. It stays, at LOW, saying it could not be confirmed."""
    mongo = FakeMongo()

    async def fetch(url):
        raise TimeoutError("slow")

    await run_dork(
        mongo=mongo,
        tenant=TENANT,
        program_id="p1",
        domain="customer.com",
        search=_search_credentials,
        fetch=fetch,
    )
    docs = await FindingRepo(mongo.collection("findings")).list("t1", "p1")
    assert len(docs) == 2
    assert all(d["severity"] == "low" and d["raw"]["verified"] is None for d in docs)
    assert all("unverified" in d["name"] for d in docs)


def test_parse_query_reads_every_operator_the_templates_use():
    from modules.dorking.templates import DORK_TEMPLATES
    from modules.dorking.verify import parse_query

    for category, templates in DORK_TEMPLATES.items():
        for t in templates:
            c = parse_query(t.format(domain="x.com"))
            assert not c.is_empty, (
                f"{category}: {t!r} parsed to nothing — it could never be verified"
            )


def test_structural_dorks_are_decided_from_the_url_without_a_fetch():
    from modules.dorking.verify import check_url, parse_query

    c = parse_query("site:x.com ext:pem OR ext:key")
    assert check_url(c, "https://x.com/certs/server.pem") is True
    assert check_url(c, "https://x.com/blog/about-keys.html") is False  # engine fuzzed ext:
    c = parse_query("site:x.com inurl:wp-admin OR inurl:phpmyadmin")
    assert check_url(c, "https://x.com/wp-admin/") is True
    assert check_url(c, "https://x.com/") is False


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
