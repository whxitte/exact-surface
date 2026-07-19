"""Server-side input validators (core.validation) — the trust-boundary checks.

These are the pure rules the API schemas enforce so a crafted request (curl/Burp,
ignoring any frontend check) is rejected before anything is persisted or acted on.
"""

from __future__ import annotations

import pytest

from core.validation import (
    normalize_apex_domain,
    normalize_cidr,
    normalize_hostname,
    validate_email_address,
    validate_public_http_url,
    validate_telegram_chat_id,
    validate_telegram_token,
)


# -- domains -----------------------------------------------------------------
@pytest.mark.parametrize(
    "raw,expected",
    [
        ("Example.COM", "example.com"),
        ("sub.example.com.", "sub.example.com"),
        ("  quipohealth.com  ", "quipohealth.com"),
        ("a-b.co", "a-b.co"),
    ],
)
def test_valid_domains_are_normalised(raw, expected):
    assert normalize_apex_domain(raw) == expected


@pytest.mark.parametrize(
    "bad",
    [
        "http://example.com",  # scheme
        "example.com/path",  # path
        "example.com:8080",  # port
        "user@example.com",  # userinfo
        "exa mple.com",  # whitespace
        "example",  # single label
        "-bad.com",  # label starts with hyphen
        "192.168.0.1",  # an IP, not a domain
        "127.0.0.1",
        "a" * 300 + ".com",  # too long
        "exa_mple.com",  # underscore not allowed
        "évil.com",  # unicode/homograph
        "",
    ],
)
def test_garbage_domains_are_rejected(bad):
    with pytest.raises(ValueError):
        normalize_apex_domain(bad)


def test_hostname_rules_match_domains():
    assert normalize_hostname("API.Example.com") == "api.example.com"
    with pytest.raises(ValueError):
        normalize_hostname("bad host")


# -- CIDRs -------------------------------------------------------------------
def test_valid_cidr_normalised():
    assert normalize_cidr("45.55.0.0/16") == "45.55.0.0/16"
    assert normalize_cidr("8.8.8.8") == "8.8.8.8/32"


@pytest.mark.parametrize("bad", ["not-a-cidr", "999.0.0.0/8", "10.0.0.0/999", ""])
def test_bad_cidr_rejected(bad):
    with pytest.raises(ValueError):
        normalize_cidr(bad)


# -- webhook URLs (SSRF surface) --------------------------------------------
@pytest.mark.parametrize(
    "url",
    ["https://discord.com/api/webhooks/1/abc", "http://hooks.slack.com/x", "https://d/h"],
)
def test_public_webhook_urls_pass(url):
    assert validate_public_http_url(url) == url


@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/latest/meta-data/",  # cloud metadata
        "https://127.0.0.1/",  # loopback
        "http://10.0.0.5/hook",  # RFC1918
        "ftp://example.com/x",  # non-http scheme
        "file:///etc/passwd",
        "notaurl",
        "https://",  # no host
    ],
)
def test_internal_or_bad_webhook_urls_rejected(url):
    with pytest.raises(ValueError):
        validate_public_http_url(url)


# -- telegram (URL-injection surface) ---------------------------------------
def test_valid_telegram_token_and_chat():
    assert validate_telegram_token("123456789:AAABBBcccDDDeeeFFFgggHHHiiiJJJkkk")
    assert validate_telegram_chat_id("-1001234567890")
    assert validate_telegram_chat_id("@my_channel")


@pytest.mark.parametrize(
    "token",
    [
        "x@169.254.169.254/",  # host-rewrite injection
        "123/../../evil",
        "no-colon-here",
        "",
    ],
)
def test_malicious_telegram_token_rejected(token):
    with pytest.raises(ValueError):
        validate_telegram_token(token)


def test_email_validation():
    assert validate_email_address("soc@company.com") == "soc@company.com"
    with pytest.raises(ValueError):
        validate_email_address("not-an-email")
