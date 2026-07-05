"""Secret extraction from JS / archived content (module 8).

Thin wrapper over the pure detection in ``core.secrets_policy``: fetches each URL
(injected fetch for offline tests) and scans the body. Fetch failures are skipped,
not fatal — one dead JS URL must not abort a scan. Binary assets (images, fonts,
media, archives) are skipped up front: they can't hold detectable secrets and
fetching them just wastes requests and spams decode errors.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from urllib.parse import urlsplit

from core.logging import logger
from core.secrets_policy import find_secrets

Fetch = Callable[[str], Awaitable[str]]

#: URL suffixes we never fetch for secret scanning (binary/asset content).
_BINARY_EXTENSIONS = frozenset(
    {
        "png", "jpg", "jpeg", "gif", "webp", "svg", "ico", "bmp", "tiff",  # images
        "woff", "woff2", "ttf", "otf", "eot",  # fonts
        "mp4", "webm", "mov", "avi", "mp3", "wav", "ogg", "flac",  # media
        "zip", "gz", "tar", "rar", "7z", "bz2",  # archives
        "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",  # documents
        "wasm", "class", "dll", "so", "dmg", "exe",  # binaries
    }
)
#: only these content-types are read as text (prefix match); anything else is skipped.
_TEXT_CONTENT_TYPES = ("text/", "application/json", "application/javascript",
                       "application/xml", "application/x-javascript", "application/xhtml")
_MAX_BODY_BYTES = 2_000_000  # don't slurp huge bodies looking for a key


def is_scannable_url(url: str) -> bool:
    """False for URLs whose extension marks them as binary/asset content."""
    path = urlsplit(url).path.rsplit(";", 1)[0]  # drop ;jsessionid etc.
    ext = path.rsplit(".", 1)[-1].lower() if "." in path.rsplit("/", 1)[-1] else ""
    return ext not in _BINARY_EXTENSIONS


async def _default_fetch(url: str) -> str:
    import aiohttp

    async with aiohttp.ClientSession() as session:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
            ctype = (resp.headers.get("Content-Type") or "").lower()
            if ctype and not any(ctype.startswith(t) for t in _TEXT_CONTENT_TYPES):
                return ""  # non-text response (image/font/binary) — nothing to scan
            raw = await resp.content.read(_MAX_BODY_BYTES)
            return raw.decode("utf-8", errors="ignore")  # lenient: never crash on bytes


def scan_content(content: str, source: str) -> list[dict]:
    """Scan already-fetched text for secrets."""
    return find_secrets(content, source)


async def scan_urls(urls: list[str], *, fetch: Fetch = _default_fetch) -> list[dict]:
    """Fetch each scannable URL and return all detected secrets across them."""
    scannable = [u for u in urls if is_scannable_url(u)]
    skipped = len(urls) - len(scannable)
    logger.info(
        "secret scan: fetching {} text endpoint(s) ({} binary/asset skipped)",
        len(scannable),
        skipped,
    )
    hits: list[dict] = []
    failed = 0
    for i, url in enumerate(scannable, 1):
        try:
            content = await fetch(url)
        except Exception as exc:  # noqa: BLE001 - one bad URL must not abort the scan
            failed += 1
            logger.debug("secret scan fetch failed for {}: {}", url, exc)
            continue
        hits.extend(find_secrets(content, url))
        if i % 50 == 0:
            logger.info("secret scan progress: {}/{} fetched", i, len(scannable))
    if failed:
        logger.info("secret scan: {} endpoint(s) failed to fetch (unreachable/expired TLS)", failed)
    return hits
