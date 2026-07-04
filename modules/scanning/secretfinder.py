"""Secret extraction from JS / archived content (module 8).

Thin wrapper over the pure detection in ``core.secrets_policy``: fetches each URL
(injected fetch for offline tests) and scans the body. Fetch failures are skipped,
not fatal — one dead JS URL must not abort a scan.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from core.logging import logger
from core.secrets_policy import find_secrets

Fetch = Callable[[str], Awaitable[str]]


async def _default_fetch(url: str) -> str:
    import aiohttp

    async with aiohttp.ClientSession() as session:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
            return await resp.text()


def scan_content(content: str, source: str) -> list[dict]:
    """Scan already-fetched text for secrets."""
    return find_secrets(content, source)


async def scan_urls(urls: list[str], *, fetch: Fetch = _default_fetch) -> list[dict]:
    """Fetch each URL and return all detected secrets across them."""
    hits: list[dict] = []
    for url in urls:
        try:
            content = await fetch(url)
        except Exception as exc:  # noqa: BLE001 - one bad URL must not abort the scan
            logger.debug("secret scan fetch failed for {}: {}", url, exc)
            continue
        hits.extend(find_secrets(content, url))
    return hits
