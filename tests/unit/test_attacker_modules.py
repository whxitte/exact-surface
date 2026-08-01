"""The new attacker-mirror modules: email security, RDAP, JS mining, broken links.

All four are pure, so these run offline. They pin the properties that decide whether the
findings are trustworthy — above all the **noise control** in JS mining, because a miner
that reports thousands of junk paths is worse than no miner at all.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from core.severity import Severity
from modules.osint import email_security as es
from modules.osint import rdap
from modules.scanning import broken_links as bl
from modules.scanning import js_miner


# --------------------------------------------------------------------------- #
# Email security
# --------------------------------------------------------------------------- #
def test_missing_spf_and_dmarc_is_spoofable():
    summary, findings = es.analyse(spf_txt=[], dmarc_txt=[])
    ids = {f.check_id for f in findings}
    assert "email-spf-missing" in ids
    assert "email-dmarc-missing" in ids
    assert summary["spoofable"] is True


def test_spf_plus_all_is_high_severity():
    _rec, findings = es.parse_spf(["v=spf1 include:_spf.google.com +all"])
    hit = next(f for f in findings if f.check_id == "email-spf-all-pass")
    assert hit.severity == Severity.HIGH


def test_multiple_spf_records_invalidate_the_policy():
    _rec, findings = es.parse_spf(["v=spf1 -all", "v=spf1 include:x.com ~all"])
    assert findings[0].check_id == "email-spf-multiple"


def test_spf_lookup_limit_flagged():
    record = "v=spf1 " + " ".join(f"include:s{i}.example.com" for i in range(12)) + " -all"
    _rec, findings = es.parse_spf([record])
    assert any(f.check_id == "email-spf-too-many-lookups" for f in findings)


def test_dmarc_reject_is_clean_and_not_spoofable():
    summary, findings = es.analyse(
        spf_txt=["v=spf1 include:_spf.google.com -all"],
        dmarc_txt=["v=DMARC1; p=reject; rua=mailto:d@x.com"],
    )
    assert summary["spoofable"] is False
    assert summary["dmarc_policy"] == "reject"
    assert findings == []


def test_dmarc_none_is_still_spoofable():
    summary, findings = es.analyse(spf_txt=["v=spf1 -all"], dmarc_txt=["v=DMARC1; p=none"])
    assert summary["spoofable"] is True
    assert any(f.check_id == "email-dmarc-policy-none" for f in findings)


def test_dmarc_partial_pct_flagged():
    _rec, findings = es.parse_dmarc(["v=DMARC1; p=reject; pct=20; rua=mailto:a@b.c"])
    assert any(f.check_id == "email-dmarc-partial-pct" for f in findings)


# --------------------------------------------------------------------------- #
# RDAP / domain intelligence
# --------------------------------------------------------------------------- #
def _rdap_payload(expiry_days: int, *, locked=True, dnssec=True) -> dict:
    exp = (datetime.now(UTC) + timedelta(days=expiry_days)).isoformat()
    return {
        "events": [
            {"eventAction": "registration", "eventDate": "2015-04-01T00:00:00Z"},
            {"eventAction": "expiration", "eventDate": exp},
        ],
        "status": ["client transfer prohibited"] if locked else ["active"],
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": [
                    "vcard",
                    [["version", {}, "text", "4.0"], ["fn", {}, "text", "Example Registrar Inc"]],
                ],
            }
        ],
        "nameservers": [{"ldhName": "NS1.EXAMPLE.COM"}],
        "secureDNS": {"delegationSigned": dnssec},
    }


def test_rdap_parses_core_fields():
    intel = rdap.parse_rdap("acme.com", _rdap_payload(200))
    assert intel.registrar == "Example Registrar Inc"
    assert intel.transfer_locked is True
    assert intel.dnssec is True
    assert intel.nameservers == ("ns1.example.com",)
    assert 195 <= (intel.days_to_expiry or 0) <= 201


def test_expiring_domain_is_high_severity():
    intel = rdap.parse_rdap("acme.com", _rdap_payload(10))
    findings = rdap.assess(intel)
    hit = next(f for f in findings if f.check_id == "domain-expiring-critical")
    assert hit.severity == Severity.HIGH


def test_already_expired_is_critical():
    intel = rdap.parse_rdap("acme.com", _rdap_payload(-5))
    assert any(f.severity == Severity.CRITICAL for f in rdap.assess(intel))


def test_missing_transfer_lock_flagged():
    intel = rdap.parse_rdap("acme.com", _rdap_payload(300, locked=False))
    assert any(f.check_id == "domain-no-transfer-lock" for f in rdap.assess(intel))


def test_healthy_domain_reports_only_informational():
    intel = rdap.parse_rdap("acme.com", _rdap_payload(300))
    assert [f.check_id for f in rdap.assess(intel)] == []


@pytest.mark.asyncio
async def test_rdap_lookup_survives_a_dead_registry():
    async def broken(_url):
        raise TimeoutError

    intel, findings = await rdap.lookup("acme.com", fetch=broken)
    assert intel is None and findings == []  # no false alarms from an outage


# --------------------------------------------------------------------------- #
# JS mining — extraction
# --------------------------------------------------------------------------- #
SAMPLE_JS = """
const API = "/api/internal/v2/users";
fetch("/api/v1/admin/settings").then(r=>r.json());
axios.get("https://staging-api.acme.com/private/keys");
const route = {path: "/dashboard/billing/invoices"};
var img = "/static/logo.png";
var css = "/assets/app.css";
const version = "/1.2.3";
const ns = "http://www.w3.org/2000/svg";
const cdn = "https://cdn.thirdparty.io/lib.js";
//# sourceMappingURL=main.js.map
"""


def test_mine_extracts_api_paths():
    out = js_miner.mine(SAMPLE_JS, "https://acme.com/static/main.js")
    values = {i.value for i in out.items}
    assert "/api/internal/v2/users" in values
    assert "/api/v1/admin/settings" in values
    assert "/dashboard/billing/invoices" in values


def test_mine_filters_assets_and_noise():
    out = js_miner.mine(SAMPLE_JS, "https://acme.com/static/main.js")
    values = {i.value for i in out.items}
    for junk in ("/static/logo.png", "/assets/app.css", "/1.2.3"):
        assert junk not in values, f"{junk} should have been filtered as noise"
    assert not any("w3.org" in v for v in values)


def test_mine_tags_interesting_paths():
    out = js_miner.mine(SAMPLE_JS, "https://acme.com/static/main.js")
    by_value = {i.value: i.tags for i in out.items}
    assert "admin" in by_value["/api/v1/admin/settings"]
    assert "api" in by_value["/api/internal/v2/users"]
    assert "internal" in by_value["/api/internal/v2/users"]


def test_mine_finds_hostnames_and_sourcemap():
    out = js_miner.mine(SAMPLE_JS, "https://acme.com/static/main.js")
    assert "staging-api.acme.com" in out.hostnames
    assert out.source_map == "https://acme.com/static/main.js.map"


def test_mine_marks_own_domain_items():
    out = js_miner.mine(SAMPLE_JS, "https://acme.com/static/main.js", own_domains=("acme.com",))
    staging = next(i for i in out.items if "staging-api" in (i.absolute or ""))
    assert "own-domain" in staging.tags


def test_library_files_are_skipped():
    assert js_miner.is_library_file("https://x.com/js/jquery-3.6.0.min.js")
    assert js_miner.is_library_file("https://x.com/static/chunk-vendors.abc.js")
    assert not js_miner.is_library_file("https://x.com/static/main.a1b2.js")


def test_new_hostnames_only_returns_unknown_owned_hosts():
    mined = [js_miner.mine(SAMPLE_JS, "https://acme.com/static/main.js")]
    fresh = js_miner.new_hostnames(mined, known={"www.acme.com"}, own_domains=("acme.com",))
    assert fresh == ["staging-api.acme.com"]  # third-party CDN excluded, known excluded


def test_discovered_paths_ranks_interesting_first():
    mined = [js_miner.mine(SAMPLE_JS, "https://acme.com/static/main.js")]
    paths = js_miner.discovered_paths(mined)
    assert paths[0].startswith("/api")  # tagged paths outrank plain ones


def test_mine_is_resilient_to_minified_garbage():
    """A real bundle is one long line of noise; extraction must not explode or flood."""
    junk = "!function(e,t){" + ("a" * 5000) + '"use strict";var n="/x";' * 50 + "}();"
    out = js_miner.mine(junk, "https://acme.com/app.js")
    assert len(out.items) < 20  # heavily filtered, not thousands of hits


# --------------------------------------------------------------------------- #
# Broken link hijacking
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_unresolvable_outbound_domain_is_hijackable():
    async def resolve(_host):
        return []  # NXDOMAIN

    link = await bl.check_link(
        "https://dead-partner.com/docs", "https://acme.com/about", resolve=resolve
    )
    assert link is not None
    assert link.kind == "unregistered-domain"
    assert link.severity == Severity.HIGH


@pytest.mark.asyncio
async def test_live_domain_is_not_reported():
    async def resolve(_host):
        return ["93.184.216.34"]

    assert (
        await bl.check_link(
            "https://live-partner.com/docs", "https://acme.com/about", resolve=resolve
        )
        is None
    )


@pytest.mark.asyncio
async def test_dead_social_handle_is_claimable():
    async def resolve(_host):
        return ["1.2.3.4"]

    async def status(_url):
        return 404

    link = await bl.check_link(
        "https://twitter.com/acmecorp", "https://acme.com/", resolve=resolve, fetch_status=status
    )
    assert link is not None and link.kind == "claimable-handle"
    assert link.platform == "X/Twitter"


def test_social_platform_detection_requires_a_handle():
    assert bl.social_platform("https://twitter.com/acme") == "X/Twitter"
    assert bl.social_platform("https://twitter.com") is None
    assert bl.social_platform("https://twitter.com/acme/status/123") is None
    assert bl.social_platform("https://twitter.com/login") is None


def test_own_domains_are_not_external():
    assert bl.is_external("https://evil.com/x", ("acme.com",)) is True
    assert bl.is_external("https://app.acme.com/x", ("acme.com",)) is False
    assert bl.is_external("https://example.com/x", ("acme.com",)) is False  # skip-listed


# --------------------------------------------------------------------------- #
# JS mining — regressions from the first real-world run (divii.ca)
# --------------------------------------------------------------------------- #
def test_script_paths_are_not_reported_as_endpoints():
    """`/js/admin.6fd71600.js` is another bundle, not an admin endpoint. The first
    real run reported it hundreds of times tagged ADMIN, which drowned the signal."""
    out = js_miner.mine('var a="/js/admin.6fd71600.js";', "https://x.com/app.js")
    assert [i.value for i in out.items] == []


def test_property_chains_are_not_reported_as_hostnames():
    """Minified code is full of `a.b.c` identifiers. Matching bare dotted strings made
    `array.prototype.find` and `legalhistory.marriageagreement` look like hosts."""
    js = '"array.prototype.find";"object.entries";"legalhistory.marriageagreement";'
    js += '"account.name";"child.dob";"string.prototype.includes";'
    assert js_miner.mine(js, "https://x.com/app.js").hostnames == []


def test_hostnames_are_still_found_in_url_context():
    js = 'fetch("https://api.internal.acme.com/v1");var w="//cdn.acme.io/x.png";'
    hosts = js_miner.mine(js, "https://acme.com/app.js").hostnames
    assert "api.internal.acme.com" in hosts
    assert "cdn.acme.io" in hosts


@pytest.mark.parametrize(
    "url",
    [
        "https://x.com/js/moment/locale/af.js",  # ~100 identical locale bundles
        "https://x.com/js/i18n/de.js",
        "https://x.com/static/vendor/thing.js",
        "https://x.com/node_modules/pkg/index.js",
        "https://x.com/js/axios.min.js",
        "https://x.com/js/core-js.bundle.js",
        "https://x.com/Promise%20based%20HTTP%20client%20node.js",  # mangled string
    ],
)
def test_third_party_and_mangled_bundles_are_skipped(url):
    assert js_miner.is_library_file(url) is True


def test_app_bundles_are_still_mined():
    for url in (
        "https://x.com/js/app.93b6cdae.js",
        "https://x.com/js/agreementsHome.79a8edf8.js",
        "https://x.com/static/main.a1b2.js",
    ):
        assert js_miner.is_library_file(url) is False


# --------------------------------------------------------------------------- #
# Domain intel is persisted as STATE, not only as findings
# --------------------------------------------------------------------------- #
async def test_domain_intel_persists_posture_for_the_ui():
    """The email/registration summary used to be computed and thrown away (only int
    stats survive into the ScanRun), so the UI had nothing to show. It is now stored."""
    from core.tenant import TenantContext
    from db.domain_intel import DomainIntelRepo
    from pipelines.domain_intel import run_domain_intel
    from tests.fakes import FakeMongo

    mongo = FakeMongo()

    async def resolve_txt(host):
        if host.startswith("_dmarc."):
            return ["v=DMARC1; p=none"]
        if "_domainkey" in host:
            return []
        return ["v=spf1 include:_spf.google.com ~all"]

    async def rdap_fetch(_url):
        return {
            "events": [{"eventAction": "expiration", "eventDate": "2027-01-01T00:00:00Z"}],
            "status": ["client transfer prohibited"],
            "entities": [
                {
                    "roles": ["registrar"],
                    "vcardArray": ["vcard", [["fn", {}, "text", "Acme Registrar"]]],
                }
            ],
            "secureDNS": {"delegationSigned": False},
        }

    res = await run_domain_intel(
        mongo=mongo,
        tenant=TenantContext("t1", "u1"),
        program_id="p1",
        apex="acme.com",
        resolve_txt=resolve_txt,
        rdap_fetch=rdap_fetch,
    )
    assert res["spoofable"] is True  # p=none does not stop spoofing

    stored = await DomainIntelRepo.from_mongo(mongo).get("t1", "p1")
    assert stored["email"]["dmarc_policy"] == "none"
    assert stored["email"]["spoofable"] is True
    assert stored["email"]["spf"].startswith("v=spf1")  # raw record kept for verification
    assert stored["registration"]["registrar"] == "Acme Registrar"
    assert stored["registration"]["transfer_locked"] is True
    assert stored["registration"]["dnssec"] is False
