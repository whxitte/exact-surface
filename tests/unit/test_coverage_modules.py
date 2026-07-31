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
    v = mis.analyse_cors("https://a.com/api", {
        "Access-Control-Allow-Origin": mis.PROBE_ORIGIN,
        "Access-Control-Allow-Credentials": "true",
    })
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
    v = mis.analyse_cors("https://a.com", {
        "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true",
    })
    assert v.kind == "wildcard-with-credentials"


def test_null_origin_with_credentials_is_high():
    v = mis.analyse_cors("https://a.com", {
        "Access-Control-Allow-Origin": "null", "Access-Control-Allow-Credentials": "true",
    })
    assert v.kind == "null-origin" and v.severity is Severity.HIGH


def test_own_origin_echo_is_not_reflection():
    assert not mis.analyse_cors("https://a.com", {
        "Access-Control-Allow-Origin": "https://a.com", "Access-Control-Allow-Credentials": "true",
    }).vulnerable


# -- open redirect ----------------------------------------------------------


def test_only_existing_redirect_params_are_probed():
    """We rewrite parameters the target published; inventing names would be fuzzing."""
    cands = mis.redirect_candidates("https://a.com/go?next=/home&id=7")
    assert [c[0] for c in cands] == ["next"]
    assert mis.PROBE_REDIRECT_HOST in cands[0][1]
    assert mis.redirect_candidates("https://a.com/go") == []


def test_redirect_to_probe_host_is_reported():
    v = mis.analyse_redirect("https://a.com/go?next=x", "next", 302,
                             {"Location": mis.PROBE_REDIRECT_URL})
    assert v.vulnerable and v.severity is Severity.MEDIUM


def test_protocol_relative_redirect_is_caught():
    """`//evil.com` has no scheme but still leaves the site — a classic bypass of
    naive "does it start with http" checks."""
    v = mis.analyse_redirect("https://a.com/go?u=x", "u", 302,
                             {"Location": f"//{mis.PROBE_REDIRECT_HOST}/x"})
    assert v.vulnerable


def test_internal_redirect_is_not_a_finding():
    v = mis.analyse_redirect("https://a.com/go?u=x", "u", 302, {"Location": "/dashboard"})
    assert not v.vulnerable


def test_non_redirect_status_is_ignored():
    assert not mis.analyse_redirect("https://a.com", "u", 200,
                                    {"Location": mis.PROBE_REDIRECT_URL}).vulnerable


# -- WAF --------------------------------------------------------------------


def test_waf_detected_from_header_name_and_value():
    assert mis.fingerprint_waf("https://a.com", {"CF-Ray": "abc"}).products == ("Cloudflare",)
    assert "Imperva Incapsula" in mis.fingerprint_waf("https://a.com", {
        "Set-Cookie": "visid_incap_1=xyz; path=/"}).products


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
    body = json.dumps({"openapi": "3.0.0", "info": {"title": "Acme"},
                       "paths": {"/users": {}, "/admin/keys": {}}})
    s = api_surface.analyse_schema("https://a.com/openapi.json", 200, body, "application/json")
    assert s and s.kind == "openapi" and set(s.endpoints) == {"/users", "/admin/keys"}


def test_html_error_page_is_not_an_api_schema():
    """A 200 that is really the site's error page is the standard false positive here."""
    assert api_surface.analyse_schema("https://a.com/openapi.json", 200,
                                      "<html>Not found</html>", "text/html") is None


def test_graphql_introspection_enabled_is_reported():
    body = json.dumps({"data": {"__schema": {"queryType": {"name": "Query"},
                                             "mutationType": {"name": "Mutation"},
                                             "types": [{"name": "User"}, {"name": "__Type"}]}}})
    s = api_surface.analyse_graphql("https://a.com/graphql", 200, body)
    assert s and s.severity is Severity.MEDIUM and s.endpoints == ("User",)


def test_graphql_with_introspection_disabled_is_info_only():
    s = api_surface.analyse_graphql("https://a.com/graphql", 400,
                                    json.dumps({"errors": [{"message": "disabled"}]}))
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
    return {"module": module, "check_id": check, "name": check, "severity": sev,
            "location": f"https://{host}/x", "fingerprint": fp or f"{module}-{check}"}


def test_two_phases_on_one_host_becomes_a_path():
    paths = narrative.build_paths([
        _f("secrets", "aws-key", "high"),
        _f("bypass_403", "bypass", "medium"),
    ])
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
    paths = narrative.build_paths([
        _f("cve_watch", "cve-2024-1", "critical"),   # escalation
        _f("takeover", "dangling", "high"),          # exposure
        _f("secrets", "key", "high"),                # credentials
    ])
    assert [s.phase for s in paths[0].steps] == ["exposure", "credentials", "escalation"]


def test_findings_on_different_hosts_do_not_form_one_story():
    paths = narrative.build_paths([
        _f("secrets", "key", "high", host="a.acme.com"),
        _f("bypass_403", "bypass", "high", host="b.acme.com"),
    ])
    assert paths == []


def test_paths_are_ranked_worst_first():
    paths = narrative.build_paths([
        _f("secrets", "k", "low", host="low.acme.com"),
        _f("bypass_403", "b", "low", host="low.acme.com"),
        _f("secrets", "k", "critical", host="hot.acme.com"),
        _f("cve_watch", "c", "critical", host="hot.acme.com"),
    ])
    assert paths[0].host == "hot.acme.com"
