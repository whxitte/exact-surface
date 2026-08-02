"""The 403/401-bypass engine (modules.http_bypass): attempt matrix + decision logic.

Pure and offline — a fake ``probe`` stands in for the network, so these exercise the
real orchestration without a socket. The key safety property (the request host is never
changed — no SSRF) is asserted directly on the generated attempts.
"""

from __future__ import annotations

from urllib.parse import urlsplit

import pytest

from modules.http_bypass import (
    ProbeResult,
    build_attempts,
    classify,
    run_bypass,
)


# -- attempt matrix ----------------------------------------------------------
def test_attempts_cover_all_three_techniques():
    techniques = {a.technique for a in build_attempts("https://x.com/admin")}
    assert techniques == {"method", "header", "path"}


def test_attempts_never_change_the_host():
    """Every candidate targets the ORIGINAL host — this is what makes the module
    SSRF-safe: spoofed values live in headers/paths, never in the connection target."""
    url = "https://secure.example.com/admin/panel"
    host = urlsplit(url).hostname
    for a in build_attempts(url):
        assert urlsplit(a.url).hostname == host


def test_method_attempts_are_safe_only():
    """No state-changing verbs — detection must never modify the target."""
    methods = {a.method for a in build_attempts("https://x.com/a") if a.technique == "method"}
    assert not (methods & {"POST", "PUT", "PATCH", "DELETE"})


def test_url_rewrite_header_targets_root_with_path_value():
    attempts = [a for a in build_attempts("https://x.com/admin") if "X-Original-URL" in a.label]
    assert attempts
    a = attempts[0]
    assert urlsplit(a.url).path == "/"
    assert a.headers["X-Original-URL"] == "/admin"


def test_path_mutations_include_canonical_tricks():
    path_attempts = [a for a in build_attempts("https://x.com/admin") if a.technique == "path"]
    labels = " ".join(a.label for a in path_attempts)
    for token in ("suffix", "..;/", "case-toggled", "url-encoded"):
        assert token in labels


# -- decision ----------------------------------------------------------------
def test_200_where_forbidden_is_high_confidence():
    base = ProbeResult(403, 120, "forbidden page")
    assert classify(base, ProbeResult(200, 5000, "the real admin panel")) == "high"


def test_identical_body_is_not_a_bypass():
    """A WAF/block page served with a 200 is not a bypass."""
    base = ProbeResult(403, 120, "ACCESS DENIED")
    assert classify(base, ProbeResult(200, 120, "ACCESS DENIED")) is None


def test_redirect_to_login_is_not_a_bypass():
    base = ProbeResult(403, 120, "x")
    assert classify(base, ProbeResult(302, 0, "", location="https://x.com/login")) is None


def test_redirect_to_resource_is_medium():
    base = ProbeResult(403, 120, "x")
    assert classify(base, ProbeResult(302, 0, "", location="https://x.com/admin/home")) == "medium"


def test_no_baseline_forbidden_means_nothing_to_bypass():
    base = ProbeResult(200, 500, "already public")
    assert classify(base, ProbeResult(200, 500, "still public")) is None


def test_url_rewrite_header_against_a_public_root_is_not_a_bypass():
    """The false positive this was built to catch: root is public on its own, so
    every X-Original-URL-style attempt 'succeeds' whether or not the header does
    anything. Root's own response, unmodified, is the control that proves it."""
    base = ProbeResult(401, 50, "unauthorized")
    homepage = ProbeResult(200, 9000, "<html>the public homepage</html>")
    candidate_via_header = ProbeResult(200, 9000, "<html>the public homepage</html>")
    assert classify(base, candidate_via_header, root_baseline=homepage) is None


def test_url_rewrite_header_that_genuinely_serves_the_forbidden_page_still_counts():
    """The guard must not blanket-suppress every rewrite-header hit — only ones that
    match what root already returns unconditionally. A header that actually reaches
    different (forbidden) content is still a real bypass."""
    base = ProbeResult(401, 50, "unauthorized")
    homepage = ProbeResult(200, 9000, "<html>the public homepage</html>")
    candidate_via_header = ProbeResult(200, 4096, "<html>the secret admin panel</html>")
    assert classify(base, candidate_via_header, root_baseline=homepage) == "high"


def test_url_rewrite_header_still_flags_when_root_is_itself_forbidden():
    """root_baseline only disables the guard when root is genuinely public. If root is
    ALSO 401/403 on its own, a header that unlocks it is real signal."""
    base = ProbeResult(401, 50, "unauthorized")
    root_also_forbidden = ProbeResult(403, 40, "forbidden")
    candidate_via_header = ProbeResult(200, 4096, "<html>the secret admin panel</html>")
    assert classify(base, candidate_via_header, root_baseline=root_also_forbidden) == "high"


# -- orchestration -----------------------------------------------------------
def _fake_probe(*, header_that_works: str | None = None, path_that_works: str | None = None):
    """A probe that returns 200 only for the one winning mutation, else 403."""

    async def probe(url: str, method: str, headers: dict[str, str]) -> ProbeResult:
        if header_that_works and header_that_works in headers:
            return ProbeResult(200, 4096, "SECRET ADMIN CONTENT")
        if path_that_works and urlsplit(url).path == path_that_works:
            return ProbeResult(200, 4096, "SECRET ADMIN CONTENT")
        return ProbeResult(403, 100, "Forbidden")

    return probe


@pytest.mark.asyncio
async def test_run_bypass_finds_header_bypass():
    result = await run_bypass(
        "https://x.com/admin", probe=_fake_probe(header_that_works="X-Original-URL")
    )
    assert result["baseline_status"] == 403
    assert result["bypasses"], "expected a bypass"
    assert any(b["label"].startswith("X-Original-URL") for b in result["bypasses"])
    assert all(b["confidence"] == "high" for b in result["bypasses"])
    # a reproduction is provided for the user
    assert all(b["curl"].startswith("curl ") for b in result["bypasses"])


@pytest.mark.asyncio
async def test_run_bypass_does_not_flag_rewrite_headers_against_a_public_root():
    """End-to-end reproduction of a real false positive: /admin is forbidden, but the
    site's root is a normal public homepage. Every X-Original-URL-style header request
    lands on root and gets root's ordinary 200 -- that must not be reported as four
    'high confidence' bypasses of /admin, which is what happened before root_baseline
    existed. A real bypass would still light up (see the header_that_works case)."""

    async def probe(url: str, method: str, headers: dict[str, str]) -> ProbeResult:
        if urlsplit(url).path in ("", "/"):
            return ProbeResult(200, 8000, "<html>public homepage</html>")
        return ProbeResult(403, 100, "Forbidden")

    result = await run_bypass("https://x.com/admin", probe=probe)
    assert result["baseline_status"] == 403
    rewrite_hits = [b for b in result["bypasses"] if "X-Original-URL" in b["label"]]
    assert not rewrite_hits, f"false-positive rewrite-header bypasses: {rewrite_hits}"


@pytest.mark.asyncio
async def test_run_bypass_finds_path_bypass():
    result = await run_bypass("https://x.com/admin", probe=_fake_probe(path_that_works="/admin/"))
    assert any(b["technique"] == "path" for b in result["bypasses"])


@pytest.mark.asyncio
async def test_run_bypass_skips_when_baseline_not_forbidden():
    async def open_probe(url, method, headers):
        return ProbeResult(200, 500, "public")

    result = await run_bypass("https://x.com/", probe=open_probe)
    assert result["skipped"] is True
    assert result["bypasses"] == []


@pytest.mark.asyncio
async def test_reconfirm_drops_a_flapping_bypass():
    """A one-off 200 that doesn't reproduce on the confirm request is discarded."""
    calls = {"n": 0}

    async def flaky(url, method, headers):
        if "X-Original-URL" in headers:
            calls["n"] += 1
            # 200 the first time it's hit, 403 on the reconfirm
            return ProbeResult(200, 4096, "x") if calls["n"] == 1 else ProbeResult(403, 100, "no")
        return ProbeResult(403, 100, "Forbidden")

    result = await run_bypass("https://x.com/admin", probe=flaky, reconfirm=True)
    assert not any(b["label"].startswith("X-Original-URL") for b in result["bypasses"])
