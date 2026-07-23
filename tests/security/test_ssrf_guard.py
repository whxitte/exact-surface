"""SSRF guard for in-process fetches (§3.10) — ExactSurface must not be steered inward.

The takeover probe and secret scanner fetch attacker-influenced targets. Without
this, an in-scope host returning ``302 -> http://169.254.169.254/`` would make
ExactSurface fetch the cloud metadata endpoint and scan the IAM credentials it returns as
a "secret". These pin the socket-level backstop that forbids any non-public target.
"""

from __future__ import annotations

import pytest

from core.netguard import is_forbidden_target_ip, is_ip_literal
from modules.safe_http import ForbiddenTarget, assert_url_allowed


@pytest.mark.parametrize(
    "ip",
    [
        "169.254.169.254",  # cloud metadata — the crown-jewel target
        "127.0.0.1",
        "10.0.0.1",
        "172.16.5.5",
        "192.168.1.1",
        "100.64.0.1",  # CGNAT
        "0.0.0.0",
        "::1",  # IPv6 loopback
        "fd00::1",  # IPv6 unique-local
        "fe80::1",  # IPv6 link-local
        "not-an-ip",  # unparseable → fail closed
    ],
)
def test_internal_and_bogus_ips_are_forbidden(ip):
    assert is_forbidden_target_ip(ip) is True


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111"])
def test_public_ips_are_allowed(ip):
    assert is_forbidden_target_ip(ip) is False


def test_ip_literal_detection():
    assert is_ip_literal("10.0.0.1")
    assert is_ip_literal("[::1]")
    assert not is_ip_literal("example.com")


def test_a_forbidden_ip_literal_url_is_refused():
    for url in (
        "http://169.254.169.254/latest/meta-data/",
        "https://127.0.0.1:8080/admin",
        "http://10.0.0.5/",
    ):
        with pytest.raises(ForbiddenTarget):
            assert_url_allowed(url)


def test_a_public_url_passes_the_precheck():
    # hostnames are validated at connect time by the resolver, not here — the
    # precheck only rejects forbidden IP *literals*, and must not false-positive.
    assert_url_allowed("https://app.customer.com/main.js")
    assert_url_allowed("http://93.184.216.34/")  # a public IP literal is fine
