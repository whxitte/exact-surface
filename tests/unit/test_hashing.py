from __future__ import annotations

from core.hashing import (
    asset_fingerprint,
    canonical_hash,
    endpoint_fingerprint,
    finding_fingerprint,
    keyed_hash,
    normalize_url,
    port_fingerprint,
    secret_fingerprint,
)

KEY = b"unit-test-key"


def test_canonical_hash_is_deterministic_and_order_independent():
    assert canonical_hash({"b": 1, "a": 2}) == canonical_hash({"a": 2, "b": 1})
    assert canonical_hash("x", 1) == canonical_hash("x", 1)
    assert canonical_hash("x", 1) != canonical_hash("x", 2)


def test_normalize_url_identity():
    n = normalize_url("HTTPS://Www.Customer.com:443/Search/?q=secret&Page=2#frag")
    assert n == "https://www.customer.com/Search?page&q"


def test_normalize_url_drops_default_port_keeps_custom():
    assert normalize_url("http://a.com:80/x") == "http://a.com/x"
    assert normalize_url("http://a.com:8080/x") == "http://a.com:8080/x"


def test_endpoint_fp_equal_across_query_values():
    a = endpoint_fingerprint("p1", "get", "https://x.customer.com/s?q=a")
    b = endpoint_fingerprint("p1", "GET", "https://x.customer.com/s?q=b")
    assert a == b


def test_endpoint_fp_differs_by_method():
    assert endpoint_fingerprint("p1", "GET", "https://x/a") != endpoint_fingerprint(
        "p1", "POST", "https://x/a"
    )


def test_asset_fp_normalizes_case_and_trailing_dot():
    assert asset_fingerprint("p1", "App.Customer.com.") == asset_fingerprint(
        "p1", "app.customer.com"
    )


def test_asset_fp_scoped_to_program():
    assert asset_fingerprint("p1", "a.customer.com") != asset_fingerprint("p2", "a.customer.com")


def test_finding_fp_differs_by_location_and_locator():
    base = finding_fingerprint("p1", "exposed-env", "https://a.customer.com")
    assert base != finding_fingerprint("p1", "exposed-env", "https://b.customer.com")
    assert base != finding_fingerprint("p1", "exposed-env", "https://a.customer.com", "param=id")


def test_port_fp():
    assert port_fingerprint("p1", "45.55.1.1", 443) != port_fingerprint("p1", "45.55.1.1", 80)


def test_secret_fp_does_not_embed_plaintext():
    secret = "AKIAZ7Q2K9WMFB3RTUVX"
    fp = secret_fingerprint("p1", secret, "https://a.customer.com/.env", KEY)
    assert secret not in fp
    # same secret + locator → same fp (dedup); different key → different fp
    assert fp == secret_fingerprint("p1", secret, "https://a.customer.com/.env", KEY)
    assert fp != secret_fingerprint("p1", secret, "https://a.customer.com/.env", b"other-key")


def test_keyed_hash_is_hmac_stable():
    assert keyed_hash("v", KEY) == keyed_hash("v", KEY)
    assert keyed_hash("v", KEY) != keyed_hash("w", KEY)
