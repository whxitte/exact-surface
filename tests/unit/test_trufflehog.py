"""trufflehog wrapper: JSON→hit mapping, verification→severity, graceful fallback,
and its integration into scan_urls alongside the regex engine."""

from __future__ import annotations

from core.errors import ToolNotFound
from core.severity import Severity
from modules.scanning.secretfinder import scan_urls
from modules.scanning.trufflehog import scan_dir


def _row(file: str, raw: str, *, detector: str = "AWS", verified: bool = False) -> dict:
    return {
        "SourceMetadata": {"Data": {"Filesystem": {"file": file}}},
        "DetectorName": detector,
        "Raw": raw,
        "Verified": verified,
    }


async def test_scan_dir_maps_file_to_url_and_severity():
    file_to_url = {"/tmp/d/0": "https://x.com/app.js", "/tmp/d/1": "https://x.com/c.json"}

    async def runner(_bin, _args, *, timeout):
        return [
            _row("/tmp/d/0", "AKIAVERIFIED", detector="AWS", verified=True),
            _row("/tmp/d/1", "ghp_unverified", detector="GitHub", verified=False),
        ]

    hits = await scan_dir("/tmp/d", file_to_url, runner=runner)

    live = next(h for h in hits if h["verified"])
    dead = next(h for h in hits if not h["verified"])
    assert live["source_locator"] == "https://x.com/app.js"
    assert live["severity"] == Severity.CRITICAL and live["kind"] == "trufflehog:aws"
    assert dead["source_locator"] == "https://x.com/c.json"
    assert dead["severity"] == Severity.HIGH


async def test_scan_dir_skips_rows_without_raw():
    async def runner(_bin, _args, *, timeout):
        return [_row("/tmp/d/0", ""), {"DetectorName": "X"}]

    assert await scan_dir("/tmp/d", {}, runner=runner) == []


async def test_scan_dir_missing_binary_is_not_an_error():
    async def runner(_bin, _args, *, timeout):
        raise ToolNotFound("trufflehog")

    assert await scan_dir("/tmp/d", {}, runner=runner) == []


async def test_scan_urls_merges_regex_and_deep_engine():
    aws = "AKIAZ7Q2K9WMFB3RTUVX"

    async def fetch(_url):
        return f"const k = '{aws}';"

    async def deep_scan(_dir, file_to_url, *, timeout):
        # trufflehog independently finds a *different*, verified secret in the body
        url = next(iter(file_to_url.values()))
        return [
            {
                "kind": "trufflehog:stripe",
                "value": "sk_live_deadbeef",
                "source_locator": url,
                "severity": Severity.CRITICAL,
                "verified": True,
            }
        ]

    hits = await scan_urls(["https://x.com/app.js"], fetch=fetch, deep_scan=deep_scan)
    kinds = {h["kind"] for h in hits}
    assert "aws_access_key" in kinds  # regex engine
    assert "trufflehog:stripe" in kinds  # deep engine


async def test_scan_urls_prefers_verified_on_duplicate():
    aws = "AKIAZ7Q2K9WMFB3RTUVX"

    async def fetch(_url):
        return f"const k = '{aws}';"

    async def deep_scan(_dir, file_to_url, *, timeout):
        url = next(iter(file_to_url.values()))
        # same secret+location the regex engine finds, but verified-live
        return [
            {
                "kind": "trufflehog:aws",
                "value": aws,
                "source_locator": url,
                "severity": Severity.CRITICAL,
                "verified": True,
            }
        ]

    hits = await scan_urls(["https://x.com/app.js"], fetch=fetch, deep_scan=deep_scan)
    same = [h for h in hits if h["value"] == aws]
    assert len(same) == 1  # de-duplicated across engines
    assert same[0]["severity"] == Severity.CRITICAL and same[0].get("verified")


async def test_scan_urls_deep_scan_disabled():
    async def fetch(_url):
        return "AKIAZ7Q2K9WMFB3RTUVX"

    hits = await scan_urls(["https://x.com/app.js"], fetch=fetch, deep_scan=None)
    assert len(hits) == 1  # regex only, no crash
