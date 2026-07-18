"""Secret extraction from JS / archived content (module 8).

Thin wrapper over the pure detection in ``core.secrets_policy``: fetches each URL
(injected fetch for offline tests) and scans the body. Fetch failures are skipped,
not fatal — one dead JS URL must not abort a scan. Binary assets (images, fonts,
media, archives) are skipped up front: they can't hold detectable secrets and
fetching them just wastes requests and spams decode errors.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import tempfile
from collections.abc import Awaitable, Callable
from urllib.parse import urlsplit

from core.logging import logger
from core.secrets_policy import find_secrets
from modules.scanning.trufflehog import scan_dir as _trufflehog_scan

Fetch = Callable[[str], Awaitable[str]]
#: robust secret engine run over the fetched bodies (trufflehog); injectable for tests.
DeepScan = Callable[..., Awaitable[list[dict]]]
DEEP_SCAN_TIMEOUT = 180.0

#: fetch many URLs at once, and cap the set — content discovery can surface tens of
#: thousands of paths and fetching each body serially would never finish in budget.
CONCURRENCY = 25
MAX_SECRET_URLS = 1500
#: high-yield content scanned first (JS/config/data often carry keys), so the cap
#: keeps the most valuable targets.
_PRIORITY_EXTENSIONS = (
    "js",
    "json",
    "env",
    "config",
    "cfg",
    "ini",
    "yml",
    "yaml",
    "txt",
    "xml",
    "map",
    "ts",
    "bak",
    "backup",
    "properties",
    "conf",
    "log",
)

#: URL suffixes we never fetch for secret scanning (binary/asset content).
_BINARY_EXTENSIONS = frozenset(
    {
        "png",
        "jpg",
        "jpeg",
        "gif",
        "webp",
        "svg",
        "ico",
        "bmp",
        "tiff",  # images
        "woff",
        "woff2",
        "ttf",
        "otf",
        "eot",  # fonts
        "mp4",
        "webm",
        "mov",
        "avi",
        "mp3",
        "wav",
        "ogg",
        "flac",  # media
        "zip",
        "gz",
        "tar",
        "rar",
        "7z",
        "bz2",  # archives
        "pdf",
        "doc",
        "docx",
        "xls",
        "xlsx",
        "ppt",
        "pptx",  # documents
        "wasm",
        "class",
        "dll",
        "so",
        "dmg",
        "exe",  # binaries
    }
)
#: only these content-types are read as text (prefix match); anything else is skipped.
_TEXT_CONTENT_TYPES = (
    "text/",
    "application/json",
    "application/javascript",
    "application/xml",
    "application/x-javascript",
    "application/xhtml",
)
_MAX_BODY_BYTES = 2_000_000  # don't slurp huge bodies looking for a key


def is_scannable_url(url: str) -> bool:
    """False for URLs whose extension marks them as binary/asset content."""
    path = urlsplit(url).path.rsplit(";", 1)[0]  # drop ;jsessionid etc.
    ext = path.rsplit(".", 1)[-1].lower() if "." in path.rsplit("/", 1)[-1] else ""
    return ext not in _BINARY_EXTENSIONS


async def _default_fetch(url: str) -> str:
    import aiohttp

    from modules.safe_http import assert_url_allowed, guarded_session

    # SSRF guard: the secret scanner reads response bodies, so a redirect/rebind to
    # the cloud metadata endpoint would get its IAM credentials scanned and stored as
    # a "secret". Redirects off + a resolver that blocks non-public IPs (§3.10).
    assert_url_allowed(url)
    async with guarded_session() as session:
        async with session.get(
            url, timeout=aiohttp.ClientTimeout(total=8), allow_redirects=False
        ) as resp:
            ctype = (resp.headers.get("Content-Type") or "").lower()
            if ctype and not any(ctype.startswith(t) for t in _TEXT_CONTENT_TYPES):
                return ""  # non-text response (image/font/binary) — nothing to scan
            raw = await resp.content.read(_MAX_BODY_BYTES)
            return raw.decode("utf-8", errors="ignore")  # lenient: never crash on bytes


def _priority(url: str) -> int:
    path = urlsplit(url).path.lower()
    return 0 if any(path.endswith("." + ext) for ext in _PRIORITY_EXTENSIONS) else 1


def _stage_body(path: str, content: str) -> None:
    """Write a fetched body to disk (in a worker thread) for the deep engine."""
    with open(path, "w", errors="ignore") as fh:
        fh.write(content)


def _dedup(hits: list[dict]) -> list[dict]:
    """Collapse the regex and trufflehog engines' hits on the same secret+location.
    Verified hits win, so a live-verified duplicate keeps its CRITICAL severity."""
    best: dict[tuple, dict] = {}
    for h in hits:
        key = (h.get("value"), h.get("source_locator"))
        cur = best.get(key)
        if cur is None or (h.get("verified") and not cur.get("verified")):
            best[key] = h
    return list(best.values())


async def scan_urls(
    urls: list[str],
    *,
    fetch: Fetch = _default_fetch,
    concurrency: int = CONCURRENCY,
    max_urls: int = MAX_SECRET_URLS,
    deep_scan: DeepScan | None = _trufflehog_scan,
    on_hit: Callable[[dict], Awaitable[None]] | None = None,
) -> list[dict]:
    """Fetch scannable URLs CONCURRENTLY and return all detected secrets.

    Two engines run over the same fetched bodies: the always-on regex detector, plus
    the robust ``deep_scan`` engine (trufflehog — 800+ detectors + live verification)
    over the bodies staged to a temp dir. ``deep_scan=None`` (or a missing binary)
    degrades gracefully to regex only. High-yield content (JS/config/data) is scanned
    first, then the set is capped — a big content-discovery haul (tens of thousands of
    paths) must never blow the stage budget by fetching every body one at a time.

    ``on_hit`` (optional) is awaited for each regex secret THE MOMENT it's found, so
    the caller can persist it immediately — a stage timeout then keeps what was found
    instead of losing the whole batch."""
    scannable = [u for u in urls if is_scannable_url(u)]
    skipped = len(urls) - len(scannable)
    scannable.sort(key=_priority)  # high-yield first, so the cap keeps the best
    capped = max(0, len(scannable) - max_urls)
    scannable = scannable[:max_urls]
    logger.info(
        "secret scan: fetching {} text endpoint(s) ({} binary skipped{}), {} at a time",
        len(scannable),
        skipped,
        f", {capped} over the cap skipped" if capped else "",
        concurrency,
    )

    sem = asyncio.Semaphore(concurrency)
    failed = 0
    tmpdir = tempfile.mkdtemp(prefix="vantari-secrets-") if deep_scan else ""
    file_to_url: dict[str, str] = {}

    async def _one(idx: int, url: str) -> list[dict]:
        nonlocal failed
        async with sem:
            try:
                content = await fetch(url)
            except Exception as exc:  # noqa: BLE001 - one bad URL must not abort the scan
                failed += 1
                logger.debug("secret scan fetch failed for {}: {}", url, exc)
                return []
        if not content:
            return []
        if tmpdir:  # stage the body on disk for the deep (trufflehog) engine
            path = os.path.join(tmpdir, str(idx))
            try:
                await asyncio.to_thread(_stage_body, path, content)
                file_to_url[path] = url
            except OSError:  # a write failure just means deep-scan misses this body
                pass
        found = find_secrets(content, url)
        if on_hit:  # stream each secret out now so a timeout doesn't lose it
            for h in found:
                await on_hit(h)
        return found

    try:
        results = await asyncio.gather(*(_one(i, u) for i, u in enumerate(scannable)))
        hits = [h for per_url in results for h in per_url]
        # How many fetches actually returned scannable text — the gap between this and
        # the fetched count is bodies filtered as non-text/empty (e.g. an SPA serving
        # index.html for every path), which is the usual reason a big haul finds nothing.
        logger.info(
            "secret scan: {} of {} fetched returned text ({} regex hit(s) so far)",
            len(file_to_url) if tmpdir else "?",
            len(scannable) - failed,
            len(hits),
        )
        if deep_scan and file_to_url:
            deep_hits = await deep_scan(tmpdir, file_to_url, timeout=DEEP_SCAN_TIMEOUT)
            if on_hit:
                for h in deep_hits:
                    await on_hit(h)
            hits += deep_hits
    finally:
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)

    if failed:
        logger.info("secret scan: {} endpoint(s) failed to fetch (unreachable/expired TLS)", failed)
    return _dedup(hits)
