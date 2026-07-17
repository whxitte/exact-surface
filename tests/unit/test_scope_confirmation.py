"""Server-side IP-scope confirmation (§9b step 3) — core/scope.confirm_ip_scope.

DNS control over an apex is not authorisation to aggressively scan every IP its
subdomains resolve to. A CIDR is promoted to DEDICATED only when it sits inside a
range genuinely announced by the ASN behind the verified apex. Everything else
stays HTTP-layer only, and a CDN edge is never dedicated even if the ASN matches.
"""

from __future__ import annotations

import pytest

from core.scope import (
    ASN_CONFIRMED_PREFIX,
    CDN_NEVER_DEDICATED,
    UNCONFIRMED,
    Action,
    IpClass,
    ProgramScope,
    ScopeEngine,
    confirm_ip_scope,
    is_asn_confirmed,
)

ENGINE = ScopeEngine.from_data_file()

# 45.55.0.0/16 is DigitalOcean (public, not a CDN feed entry) — a realistic
# "customer owns a dedicated block" case.
APEX_RANGES = ["45.55.0.0/16"]


def _one(cidrs, ranges=APEX_RANGES):
    out = confirm_ip_scope(cidrs, ranges, engine=ENGINE)
    return out[0] if out else None


def test_cidr_inside_apex_asn_range_is_confirmed_dedicated():
    e = _one(["45.55.1.0/24"])
    assert e["ip_class"] == IpClass.DEDICATED.value
    assert e["confirmed_via"] == f"{ASN_CONFIRMED_PREFIX}45.55.0.0/16"
    assert Action.PORT_SCAN.value in e["action_set"]
    assert is_asn_confirmed(e)


def test_cidr_outside_apex_asn_range_stays_http_only():
    """The P0: declaring someone else's block must not grant port scanning."""
    e = _one(["8.8.8.0/24"])
    assert e["ip_class"] != IpClass.DEDICATED.value
    assert e["confirmed_via"] == UNCONFIRMED
    assert Action.PORT_SCAN.value not in e["action_set"]
    assert Action.HTTP_PROBE.value in e["action_set"]
    assert not is_asn_confirmed(e)


def test_cdn_range_is_never_dedicated_even_if_asn_matches():
    """A Cloudflare-fronted apex announces Cloudflare ranges; those edges still
    belong to Cloudflare, so they can never be promoted."""
    e = _one(["104.16.0.0/16"], ranges=["104.16.0.0/12"])  # 'matching' ASN range
    assert e["ip_class"] == IpClass.CDN.value
    assert e["confirmed_via"] == CDN_NEVER_DEDICATED
    assert Action.PORT_SCAN.value not in e["action_set"]
    assert not is_asn_confirmed(e)


@pytest.mark.parametrize(
    "cidr", ["10.0.0.0/8", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10"]
)
def test_hard_deny_ranges_are_never_recorded(cidr):
    # Not merely unconfirmed — never authorisable, so not recorded at all.
    assert confirm_ip_scope([cidr], ["10.0.0.0/8"], engine=ENGINE) == []


def test_invalid_cidrs_are_dropped_not_trusted():
    assert confirm_ip_scope(["not-a-cidr", "", "999.1.1.1/24"], APEX_RANGES, engine=ENGINE) == []


def test_no_apex_ranges_confirms_nothing():
    """asnmap unavailable ⇒ nothing is confirmed (fail safe, never fail open)."""
    e = _one(["45.55.1.0/24"], ranges=[])
    assert e["confirmed_via"] == UNCONFIRMED
    assert Action.PORT_SCAN.value not in e["action_set"]


def test_is_asn_confirmed_rejects_client_supplied_markers():
    for via in ("whois:AS14061", "acknowledged_shared", "pending", "", "asnmap"):
        assert not is_asn_confirmed({"ip_class": "dedicated", "confirmed_via": via})
    assert is_asn_confirmed({"ip_class": "dedicated", "confirmed_via": "asnmap:45.55.0.0/16"})


# -- defence in depth inside the engine itself -------------------------------
def test_cdn_ip_inside_authorized_cidr_stays_http_only():
    """Even if a bad/stale dedicated CIDR covers a CDN edge, evaluate() must not
    grant port scanning — the CDN class wins."""
    scope = ProgramScope(
        verified_apexes=("customer.com",),
        authorized_dedicated_cidrs=("104.16.0.0/12",),  # wrongly covers Cloudflare
    )
    d = ENGINE.evaluate("www.customer.com", ["104.16.5.5"], scope)
    assert d.allowed
    assert d.ip_class == IpClass.CDN
    assert Action.PORT_SCAN not in d.actions
    assert Action.HTTP_PROBE in d.actions


def test_public_ip_inside_authorized_cidr_still_gets_full_actions():
    """The legitimate path must keep working: a confirmed dedicated block grants full."""
    scope = ProgramScope(
        verified_apexes=("customer.com",),
        authorized_dedicated_cidrs=("45.55.0.0/16",),
    )
    d = ENGINE.evaluate("app.customer.com", ["45.55.1.1"], scope)
    assert d.allowed and d.ip_class == IpClass.DEDICATED
    assert Action.PORT_SCAN in d.actions
