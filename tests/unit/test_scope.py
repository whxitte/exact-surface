"""Exhaustive tests for the central scope engine — the most important control.

If any of these fail, Vantari could scan something it must never touch. Treat a
failure here as a release blocker.
"""

from __future__ import annotations

import pytest

from core.errors import OutOfScope
from core.scope import (
    Action,
    IpClass,
    ProgramScope,
    ScopeEngine,
    assert_in_scope,
)

ENGINE = ScopeEngine.from_data_file()

SCOPE = ProgramScope(
    verified_apexes=("customer.com",),
    excluded_hosts=frozenset({"legacy.customer.com"}),
    excluded_cidrs=("45.55.99.0/24",),
    authorized_dedicated_cidrs=("45.55.0.0/16",),
)


# --------------------------------------------------------------------------- #
# classify_ip
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "ip,expected",
    [
        ("10.0.0.1", IpClass.PRIVATE),
        ("172.16.5.4", IpClass.PRIVATE),
        ("192.168.1.1", IpClass.PRIVATE),
        ("127.0.0.1", IpClass.LOOPBACK),
        ("169.254.169.254", IpClass.LINK_LOCAL),  # cloud metadata — must be caught
        ("169.254.0.1", IpClass.LINK_LOCAL),
        ("100.64.0.1", IpClass.CGNAT),
        ("224.0.0.1", IpClass.MULTICAST),
        ("0.0.0.0", IpClass.UNSPECIFIED),
        ("104.16.5.5", IpClass.CDN),        # cloudflare
        ("151.101.1.1", IpClass.CDN),       # fastly
        ("8.8.8.8", IpClass.PUBLIC),        # routable, ownership unknown
        ("not-an-ip", IpClass.RESERVED),    # fail closed
    ],
)
def test_classify_ip(ip, expected):
    assert ENGINE.classify_ip(ip) == expected


def test_classify_never_returns_dedicated():
    # DEDICATED is an ownership decision, not an address property.
    for ip in ("8.8.8.8", "45.55.1.1", "104.16.5.5"):
        assert ENGINE.classify_ip(ip) != IpClass.DEDICATED


# --------------------------------------------------------------------------- #
# evaluate — denials
# --------------------------------------------------------------------------- #
def test_out_of_scope_host_denied():
    d = ENGINE.evaluate("app.attacker.com", ["45.55.1.1"], SCOPE)
    assert not d.allowed and "verified apex" in d.reason


def test_excluded_host_denied():
    d = ENGINE.evaluate("legacy.customer.com", ["45.55.1.1"], SCOPE)
    assert not d.allowed and "exclusion" in d.reason


def test_excluded_cidr_denied():
    d = ENGINE.evaluate("x.customer.com", ["45.55.99.5"], SCOPE)
    assert not d.allowed and "exclusion" in d.reason


@pytest.mark.parametrize("ip", ["169.254.169.254", "10.0.0.5", "127.0.0.1", "100.64.0.9"])
def test_internal_ip_poisons_host(ip):
    # Even a legitimately in-scope subdomain is denied if it resolves internal.
    d = ENGINE.evaluate("app.customer.com", [ip], SCOPE)
    assert not d.allowed


def test_one_bad_ip_among_good_denies_all():
    d = ENGINE.evaluate("app.customer.com", ["45.55.1.1", "169.254.169.254"], SCOPE)
    assert not d.allowed


# --------------------------------------------------------------------------- #
# evaluate — action sets
# --------------------------------------------------------------------------- #
def test_dedicated_gets_full_actions():
    d = ENGINE.evaluate("app.customer.com", ["45.55.1.1"], SCOPE)
    assert d.allowed and d.ip_class == IpClass.DEDICATED
    for a in (Action.PORT_SCAN, Action.ACTIVE_SCAN, Action.CONTENT_DISCOVERY):
        assert d.permits(a)


def test_cdn_is_http_only():
    d = ENGINE.evaluate("www.customer.com", ["104.16.5.5"], SCOPE)
    assert d.allowed and d.ip_class == IpClass.CDN
    assert d.permits(Action.HTTP_PROBE)
    assert not d.permits(Action.PORT_SCAN)
    assert not d.permits(Action.ACTIVE_SCAN)


def test_unconfirmed_public_is_http_only():
    d = ENGINE.evaluate("api.customer.com", ["8.8.8.8"], SCOPE)
    assert d.allowed and not d.permits(Action.PORT_SCAN)


def test_mixed_dedicated_and_cdn_is_http_only():
    d = ENGINE.evaluate("cdn.customer.com", ["45.55.1.1", "104.16.5.5"], SCOPE)
    assert d.allowed and not d.permits(Action.PORT_SCAN)


def test_no_resolved_ips_is_passive_only():
    d = ENGINE.evaluate("ghost.customer.com", [], SCOPE)
    assert d.allowed and d.permits(Action.PASSIVE_RECON)
    assert not d.permits(Action.HTTP_PROBE)


def test_apex_itself_in_scope():
    d = ENGINE.evaluate("customer.com", ["45.55.1.1"], SCOPE)
    assert d.allowed


# --------------------------------------------------------------------------- #
# decision.require + assert_in_scope
# --------------------------------------------------------------------------- #
def test_require_raises_when_action_not_permitted():
    d = ENGINE.evaluate("www.customer.com", ["104.16.5.5"], SCOPE)
    with pytest.raises(OutOfScope):
        d.require(Action.PORT_SCAN)
    d.require(Action.HTTP_PROBE)  # permitted → no raise


async def test_assert_in_scope_allows_and_denies():
    async def resolver_ok(_host):
        return ["45.55.1.1"]

    async def resolver_bad(_host):
        return ["169.254.169.254"]

    decision = await assert_in_scope("app.customer.com", SCOPE, resolver_ok, ENGINE)
    assert decision.permits(Action.PORT_SCAN)

    with pytest.raises(OutOfScope):
        await assert_in_scope("app.customer.com", SCOPE, resolver_bad, ENGINE)
