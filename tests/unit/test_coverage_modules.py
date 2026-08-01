"""Attacker-coverage modules: CORS, open redirect, WAF, API surface, typosquat,
dependency confusion, attack-path narrative. Pure functions — no network, no DB."""

from __future__ import annotations

import json

from core.severity import Severity
from modules.intelligence import narrative
from modules.osint import dependency_confusion as dc
from modules.osint import typosquat
from modules.scanning import api_surface
from modules.scanning import http_misconfig as mis

# -- CORS -------------------------------------------------------------------


def test_reflected_origin_with_credentials_is_high():
    v = mis.analyse_cors(
        "https://a.com/api",
        {
            "Access-Control-Allow-Origin": mis.PROBE_ORIGIN,
            "Access-Control-Allow-Credentials": "true",
        },
    )
    assert v.vulnerable and v.severity is Severity.HIGH and v.kind == "reflected-origin"


def test_reflected_origin_without_credentials_is_low_not_high():
    """Reflection without credentials cannot read authenticated data — saying HIGH
    would be the kind of inflation that makes a scanner untrustworthy."""
    v = mis.analyse_cors("https://a.com", {"Access-Control-Allow-Origin": mis.PROBE_ORIGIN})
    assert v.vulnerable and v.severity is Severity.LOW


def test_plain_wildcard_is_not_a_finding():
    """`*` alone is how every public API is configured; browsers refuse credentials
    with it. Reporting it would bury the real ones."""
    assert not mis.analyse_cors("https://a.com", {"Access-Control-Allow-Origin": "*"}).vulnerable


def test_wildcard_with_credentials_is_flagged():
    v = mis.analyse_cors(
        "https://a.com",
        {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        },
    )
    assert v.kind == "wildcard-with-credentials"


def test_null_origin_with_credentials_is_high():
    v = mis.analyse_cors(
        "https://a.com",
        {
            "Access-Control-Allow-Origin": "null",
            "Access-Control-Allow-Credentials": "true",
        },
    )
    assert v.kind == "null-origin" and v.severity is Severity.HIGH


def test_own_origin_echo_is_not_reflection():
    assert not mis.analyse_cors(
        "https://a.com",
        {
            "Access-Control-Allow-Origin": "https://a.com",
            "Access-Control-Allow-Credentials": "true",
        },
    ).vulnerable


# -- open redirect ----------------------------------------------------------


def test_only_existing_redirect_params_are_probed():
    """We rewrite parameters the target published; inventing names would be fuzzing."""
    cands = mis.redirect_candidates("https://a.com/go?next=/home&id=7")
    assert [c[0] for c in cands] == ["next"]
    assert mis.PROBE_REDIRECT_HOST in cands[0][1]
    assert mis.redirect_candidates("https://a.com/go") == []


def test_redirect_to_probe_host_is_reported():
    v = mis.analyse_redirect(
        "https://a.com/go?next=x", "next", 302, {"Location": mis.PROBE_REDIRECT_URL}
    )
    assert v.vulnerable and v.severity is Severity.MEDIUM


def test_protocol_relative_redirect_is_caught():
    """`//evil.com` has no scheme but still leaves the site — a classic bypass of
    naive "does it start with http" checks."""
    v = mis.analyse_redirect(
        "https://a.com/go?u=x", "u", 302, {"Location": f"//{mis.PROBE_REDIRECT_HOST}/x"}
    )
    assert v.vulnerable


def test_internal_redirect_is_not_a_finding():
    v = mis.analyse_redirect("https://a.com/go?u=x", "u", 302, {"Location": "/dashboard"})
    assert not v.vulnerable


def test_non_redirect_status_is_ignored():
    assert not mis.analyse_redirect(
        "https://a.com", "u", 200, {"Location": mis.PROBE_REDIRECT_URL}
    ).vulnerable


# -- WAF --------------------------------------------------------------------


def test_waf_detected_from_header_name_and_value():
    assert mis.fingerprint_waf("https://a.com", {"CF-Ray": "abc"}).products == ("Cloudflare",)
    assert (
        "Imperva Incapsula"
        in mis.fingerprint_waf(
            "https://a.com", {"Set-Cookie": "visid_incap_1=xyz; path=/"}
        ).products
    )


def test_no_waf_is_reported_as_unprotected():
    assert not mis.fingerprint_waf("https://a.com", {"Server": "nginx"}).protected


# -- robots / sitemap -------------------------------------------------------


def test_robots_disallow_becomes_paths_and_flags_the_juicy_ones():
    paths, sitemaps = api_surface.parse_robots(
        "User-agent: *\nDisallow: /admin/\nDisallow: /assets/\nSitemap: https://a.com/sitemap.xml\n",
        "https://a.com/",
    )
    by_path = {p.path: p for p in paths}
    assert by_path["https://a.com/admin/"].interesting
    assert not by_path["https://a.com/assets/"].interesting
    assert sitemaps == ["https://a.com/sitemap.xml"]


def test_robots_blanket_disallow_is_not_a_path():
    """`Disallow: /` means "index nothing" — it is not a hidden directory."""
    paths, _ = api_surface.parse_robots("Disallow: /\n", "https://a.com/")
    assert paths == []


def test_sitemap_urls_are_extracted_and_bounded():
    body = "<urlset>" + "".join(f"<loc>https://a.com/p{i}</loc>" for i in range(50)) + "</urlset>"
    assert len(api_surface.parse_sitemap(body, limit=10)) == 10


# -- API schemas ------------------------------------------------------------


def test_openapi_schema_yields_its_routes():
    body = json.dumps(
        {"openapi": "3.0.0", "info": {"title": "Acme"}, "paths": {"/users": {}, "/admin/keys": {}}}
    )
    s = api_surface.analyse_schema("https://a.com/openapi.json", 200, body, "application/json")
    assert s and s.kind == "openapi" and set(s.endpoints) == {"/users", "/admin/keys"}


def test_html_error_page_is_not_an_api_schema():
    """A 200 that is really the site's error page is the standard false positive here."""
    assert (
        api_surface.analyse_schema(
            "https://a.com/openapi.json", 200, "<html>Not found</html>", "text/html"
        )
        is None
    )


def test_graphql_introspection_enabled_is_reported():
    body = json.dumps(
        {
            "data": {
                "__schema": {
                    "queryType": {"name": "Query"},
                    "mutationType": {"name": "Mutation"},
                    "types": [{"name": "User"}, {"name": "__Type"}],
                }
            }
        }
    )
    s = api_surface.analyse_graphql("https://a.com/graphql", 200, body)
    assert s and s.severity is Severity.MEDIUM and s.endpoints == ("User",)


def test_graphql_with_introspection_disabled_is_info_only():
    s = api_surface.analyse_graphql(
        "https://a.com/graphql", 400, json.dumps({"errors": [{"message": "disabled"}]})
    )
    assert s and s.severity is Severity.INFO


# -- typosquat --------------------------------------------------------------


def test_generate_covers_the_real_techniques_and_never_returns_the_original():
    cands = dict(typosquat.generate("acme.com"))
    assert "acme.com" not in cands
    assert "acrne.com" in cands or "acme.co" in cands
    assert "secure-acme.com" in cands and "acme.co" in cands
    assert all(c.count(" ") == 0 for c in cands)


def test_generation_is_bounded():
    assert len(typosquat.generate("averylongcompanyname.com", limit=25)) == 25


def test_lookalike_with_mx_outranks_one_without():
    """MX means the phishing plumbing is already installed."""
    with_mx = typosquat.Lookalike("acrne.com", "a homoglyph substitution", ("1.2.3.4",), True)
    without = typosquat.Lookalike("acrne.com", "a homoglyph substitution", ("1.2.3.4",), False)
    assert with_mx.severity is Severity.HIGH and without.severity is Severity.MEDIUM
    assert "MX" in with_mx.evidence


def test_multi_part_tld_survives():
    assert any(c.endswith(".co.uk") is False for c, _ in typosquat.generate("acme.co.uk"))
    assert all("acme.co.uk" != c for c, _ in typosquat.generate("acme.co.uk"))


# -- dependency confusion ---------------------------------------------------


def test_scoped_internal_package_is_extracted():
    body = 'import x from "@acme-internal/auth-client";'
    pkgs = dc.extract_packages(body, "https://a.com/app.js")
    assert any(p.name == "@acme-internal/auth-client" and p.scoped for p in pkgs)


def test_known_public_scopes_are_ignored():
    pkgs = dc.extract_packages('require("@babel/runtime/helpers")', "https://a.com/app.js")
    assert not any(p.name.startswith("@babel") for p in pkgs)


def test_unregistered_package_is_a_finding_and_registered_one_is_not():
    pkg = dc.PackageRef("@acme/secret-sdk", "https://a.com/app.js", True)
    risk = dc.assess(pkg, 404)
    assert risk and risk.severity is Severity.HIGH
    assert "Register" in risk.remediation
    assert dc.assess(pkg, 200) is None


def test_unscoped_miss_is_lower_confidence_than_scoped():
    scoped = dc.assess(dc.PackageRef("@acme/x", "u", True), 404)
    plain = dc.assess(dc.PackageRef("acme-x", "u", False), 404)
    assert scoped.severity is Severity.HIGH and plain.severity is Severity.MEDIUM


# -- attack-path narrative --------------------------------------------------


def _f(module, check, sev, host="app.acme.com", fp=None):
    return {
        "module": module,
        "check_id": check,
        "name": check,
        "severity": sev,
        "location": f"https://{host}/x",
        "fingerprint": fp or f"{module}-{check}",
    }


def test_two_phases_on_one_host_becomes_a_path():
    paths = narrative.build_paths(
        [
            _f("secrets", "aws-key", "high"),
            _f("bypass_403", "bypass", "medium"),
        ]
    )
    assert len(paths) == 1
    p = paths[0]
    assert p.host == "app.acme.com" and p.is_real_path
    assert [s.phase for s in p.steps] == ["credentials", "access"]
    assert all(s.finding_id for s in p.steps), "every step must link to its evidence"


def test_a_single_finding_is_not_called_an_attack_chain():
    """Inflating one finding into a "chain" is exactly the dishonesty this product
    exists to avoid."""
    assert narrative.build_paths([_f("secrets", "aws-key", "high")]) == []


def test_steps_are_ordered_by_attacker_phase_not_discovery_order():
    paths = narrative.build_paths(
        [
            _f("cve_watch", "cve-2024-1", "critical"),  # escalation
            _f("takeover", "dangling", "high"),  # exposure
            _f("secrets", "key", "high"),  # credentials
        ]
    )
    assert [s.phase for s in paths[0].steps] == ["exposure", "credentials", "escalation"]


def test_findings_on_different_hosts_do_not_form_one_story():
    paths = narrative.build_paths(
        [
            _f("secrets", "key", "high", host="a.acme.com"),
            _f("bypass_403", "bypass", "high", host="b.acme.com"),
        ]
    )
    assert paths == []


def test_paths_are_ranked_worst_first():
    paths = narrative.build_paths(
        [
            _f("secrets", "k", "low", host="low.acme.com"),
            _f("bypass_403", "b", "low", host="low.acme.com"),
            _f("secrets", "k", "critical", host="hot.acme.com"),
            _f("cve_watch", "c", "critical", host="hot.acme.com"),
        ]
    )
    assert paths[0].host == "hot.acme.com"


# -- parameter discovery ----------------------------------------------------


def test_observed_params_cost_nothing_and_come_from_our_own_data():
    from modules.scanning import params as P

    obs = P.extract_observed(
        [
            "https://a.com/r?debug=1&id=5",
            "https://a.com/r?id=6",
            "https://a.com/plain",
        ]
    )
    by_name = {o.name: o for o in obs}
    assert set(by_name) == {"debug", "id"}
    assert by_name["id"].values_seen == 2  # two distinct values seen
    assert by_name["debug"].notable is not None


def test_probe_url_preserves_existing_query():
    from modules.scanning import params as P

    out = P.probe_url("https://a.com/r?id=5", ["debug"])
    assert "id=5" in out and "debug=exactsurface" in out


def test_batch_that_changes_nothing_eliminates_every_param_in_it():
    """One request rules out a dozen names — this is what keeps the probe bounded."""
    from modules.scanning import params as P

    base = P.Baseline("https://a.com/r", 200, 1000)
    assert P.analyse_batch(base, ["a", "b", "c"], 200, "x" * 1010) is False
    assert P.analyse_batch(base, ["a", "b", "c"], 200, "x" * 1200) is True
    assert P.analyse_batch(base, ["a"], 500, "x" * 1000) is True


def test_small_length_jitter_is_not_a_finding():
    """Pages carry per-request noise — timestamps, CSRF tokens. A few bytes is not
    a signal, and treating it as one would make every page a finding."""
    from modules.scanning import params as P

    base = P.Baseline("https://a.com/r", 200, 1000)
    assert P.classify("debug", base, 200, "x" * 1020) is None


def test_reflection_raises_severity_but_is_not_called_xss():
    from modules.scanning import params as P

    base = P.Baseline("https://a.com/r", 200, 1000)
    hit = P.classify("format", base, 200, "hello exactsurface world")
    assert hit and hit.reflected and hit.severity is Severity.MEDIUM
    assert "xss" not in hit.evidence.lower() and "inert" in hit.evidence


def test_admin_flag_outranks_a_generic_parameter():
    from modules.scanning import params as P

    base = P.Baseline("https://a.com/r", 200, 1000)
    admin = P.classify("is_admin", base, 200, "x" * 1200)
    plain = P.classify("sort", base, 200, "x" * 1200)
    assert admin.severity is Severity.HIGH and plain.severity is Severity.LOW


# -- reverse DNS ------------------------------------------------------------


def test_oversized_range_is_refused_not_truncated():
    """A /8 in a scope entry is a mistake. Quietly sweeping its first 4096 addresses
    would hide the mistake and still generate the traffic."""
    from modules.recon import reverse_dns as rd

    assert rd.expand("10.0.0.0/8") == []
    assert rd.expand("192.168.1.0/24")[:1] == ["192.168.1.1"]
    assert len(rd.expand("10.1.0.0/20")) == 4094


def test_non_networks_and_ipv6_are_refused():
    from modules.recon import reverse_dns as rd

    assert rd.expand("not-a-cidr") == []
    assert rd.expand("2001:db8::/32") == []


def test_expand_all_dedupes_and_caps_globally():
    from modules.recon import reverse_dns as rd

    out = rd.expand_all(["192.168.1.0/24", "192.168.1.0/24"], total=50)
    assert len(out) == 50 and len(set(out)) == 50


def test_provider_default_ptr_is_not_a_discovery():
    """ec2-1-2-3-4.compute.amazonaws.com encodes the IP, not an identity. Reporting
    these would bury the handful of real names in thousands of rows."""
    from modules.recon import reverse_dns as rd

    assert rd.classify("1.2.3.4", "ec2-1-2-3-4.compute.amazonaws.com", ("acme.com",)) is None
    assert rd.classify("1.2.3.4", "", ("acme.com",)) is None


def test_in_scope_reverse_hit_is_new_surface():
    from modules.recon import reverse_dns as rd

    hit = rd.classify("1.2.3.4", "jenkins.acme.com", ("acme.com",))
    assert hit and hit.in_scope and hit.is_new_surface
    other = rd.classify("1.2.3.4", "mail.partner.com", ("acme.com",))
    assert other and not other.in_scope


# -- cloud asset inventory (cloudlist) ---------------------------------------


def test_cloudlist_parses_names_and_public_ips():
    from modules.recon import cloudlist as cl

    assets = cl.parse(
        [
            {"provider": "aws", "dns_name": "lb-1.acme.com", "public_ipv4": "93.184.216.34"},
            {"provider": "gcp", "hostname": "vm-old.acme.com"},
        ]
    )
    by_value = {a.value: a for a in assets}
    assert by_value["lb-1.acme.com"].provider == "aws"
    assert by_value["93.184.216.34"].is_ip and by_value["93.184.216.34"].ip == "93.184.216.34"
    assert not by_value["vm-old.acme.com"].is_ip


def test_private_addresses_are_dropped():
    """Real assets, but not EXTERNAL attack surface — and this product only speaks
    about what an outsider can reach."""
    from modules.recon import cloudlist as cl

    # NOTE: 203.0.113.x and friends are documentation ranges and Python's ipaddress
    # reports them as private, so a real public address is needed here.
    assets = cl.parse(
        [
            {"provider": "aws", "public_ipv4": "10.0.0.5"},
            {"provider": "aws", "public_ipv4": "127.0.0.1"},
            {"provider": "aws", "public_ipv4": "93.184.216.34"},
        ]
    )
    assert [a.value for a in assets] == ["93.184.216.34"]


def test_parse_is_bounded_and_deduped():
    from modules.recon import cloudlist as cl

    rows = [{"provider": "aws", "dns_name": f"h{i}.acme.com"} for i in range(10)]
    assert len(cl.parse(rows + rows)) == 10


def test_malformed_rows_never_raise():
    from modules.recon import cloudlist as cl

    assert cl.parse([None, "nonsense", {}, {"provider": "aws"}]) == []


async def test_missing_binary_degrades_to_empty_not_an_error():
    from core.errors import ToolNotFound
    from modules.recon import cloudlist as cl

    async def missing(*a, **k):
        raise ToolNotFound("cloudlist")

    assert await cl.enumerate_assets("/tmp/cfg.yaml", 10, runner=missing) == []
    assert await cl.enumerate_assets("", 10) == []  # no config → no attempt


async def test_cloud_assets_outside_a_verified_domain_are_reported_never_scanned():
    """The most valuable output of the module — shadow IT — must be surfaced as a
    finding and NOT turned into scannable assets. The cloud provider confirming
    ownership is not the customer proving authorisation (§9b)."""
    from core.scope import ProgramScope
    from core.tenant import TenantContext
    from modules.recon.cloudlist import CloudAsset
    from pipelines.cloud_assets import run_cloud_assets
    from tests.fakes import FakeMongo

    mongo = FakeMongo()

    async def fake_enum(config, timeout):
        return [
            CloudAsset("app.acme.com", "aws"),
            CloudAsset("forgotten.other-brand.com", "aws"),
            CloudAsset("93.184.216.34", "aws", is_ip=True),
        ]

    result = await run_cloud_assets(
        mongo=mongo,
        scope=ProgramScope(verified_apexes=("acme.com",)),
        tenant=TenantContext("t1"),
        program_id="p1",
        config_path="/tmp/cfg.yaml",
        enumerate_fn=fake_enum,
    )
    assert result["in_scope"] == 1 and result["outside_scope"] == 2
    stored = await mongo.collection("assets").find({}).to_list(None)
    assert [a["hostname"] for a in stored] == ["app.acme.com"]
    findings = await mongo.collection("findings").find({}).to_list(None)
    assert len(findings) == 1
    assert "not covered by a verified domain" in findings[0]["name"]


async def test_cloud_assets_without_credentials_says_so_rather_than_finding_nothing():
    from core.scope import ProgramScope
    from core.tenant import TenantContext
    from pipelines.cloud_assets import run_cloud_assets
    from tests.fakes import FakeMongo

    result = await run_cloud_assets(
        mongo=FakeMongo(),
        scope=ProgramScope(verified_apexes=("acme.com",)),
        tenant=TenantContext("t1"),
        program_id="p1",
        config_path="",
    )
    assert result["skipped"] and "READ-ONLY" in result["note"]


# -- dangling A-records (takeover, different record type) ---------------------


def _cloud(ip: str) -> str:
    return "cloud_shared" if ip.startswith("13.32.") else "dedicated"


def test_pooled_cloud_ip_with_nothing_answering_is_dangling():
    from modules.takeover import find_dangling_a_records

    hits = find_dangling_a_records(
        [{"hostname": "gone.acme.com", "resolved_ips": ["13.32.1.1"], "dns_records": {}}],
        classify=_cloud,
        alive_hosts=set(),
    )
    assert [h.host for h in hits] == ["gone.acme.com"]
    assert "returns to the provider's pool" in hits[0].evidence
    assert "Delete the A record" in hits[0].remediation


def test_a_host_that_is_alive_is_never_dangling():
    """It is serving traffic. Whatever its address class, something is behind it."""
    from modules.takeover import find_dangling_a_records

    assert (
        find_dangling_a_records(
            [{"hostname": "live.acme.com", "resolved_ips": ["13.32.1.1"], "dns_records": {}}],
            classify=_cloud,
            alive_hosts={"live.acme.com"},
        )
        == []
    )


def test_an_ip_the_customer_owns_is_not_dangling():
    """Dedicated address space is not a provider pool — nobody else can receive it."""
    from modules.takeover import find_dangling_a_records

    assert (
        find_dangling_a_records(
            [{"hostname": "own.acme.com", "resolved_ips": ["198.51.100.9"], "dns_records": {}}],
            classify=_cloud,
            alive_hosts=set(),
        )
        == []
    )


def test_a_host_with_a_cname_is_left_to_the_cname_check():
    """Reporting both would double-count the same exposure under two names."""
    from modules.takeover import find_dangling_a_records

    assert (
        find_dangling_a_records(
            [
                {
                    "hostname": "cn.acme.com",
                    "resolved_ips": ["13.32.1.1"],
                    "dns_records": {"cname": ["x.s3.amazonaws.com"]},
                }
            ],
            classify=_cloud,
            alive_hosts=set(),
        )
        == []
    )


def test_unmonitored_assets_are_skipped():
    from modules.takeover import find_dangling_a_records

    assert (
        find_dangling_a_records(
            [
                {
                    "hostname": "muted.acme.com",
                    "resolved_ips": ["13.32.1.1"],
                    "dns_records": {},
                    "monitored": False,
                }
            ],
            classify=_cloud,
            alive_hosts=set(),
        )
        == []
    )
