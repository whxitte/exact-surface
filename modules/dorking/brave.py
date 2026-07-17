"""Brave Search API wrapper (module 20).

Returns the same ``{title, link, snippet}`` shape as the Google CSE and SerpAPI
wrappers so ``pipelines/dork.py`` can swap engines without caring which is
configured. Injectable fetch for offline tests; no key → no results (never an
error, so an unconfigured engine simply contributes nothing).

Brave authenticates with a header, not a query param — hence the ``(url, headers)``
fetch signature shared with the other header-authenticated engines.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from urllib.parse import quote_plus

Fetch = Callable[..., Awaitable[dict]]

_ENDPOINT = "https://api.search.brave.com/res/v1/web/search"


async def _default_fetch(url: str, headers: dict | None = None) -> dict:  # pragma: no cover
    import aiohttp

    async with aiohttp.ClientSession() as session:
        async with session.get(
            url, headers=headers or {}, timeout=aiohttp.ClientTimeout(total=20)
        ) as resp:
            return await resp.json(content_type=None)


async def search(
    query: str, *, key: str | None = None, fetch: Fetch = _default_fetch
) -> list[dict]:
    if not key:
        return []
    url = f"{_ENDPOINT}?q={quote_plus(query)}"
    data = await fetch(url, {"X-Subscription-Token": key, "Accept": "application/json"})
    results = (data.get("web") or {}).get("results") or []
    return [
        {"title": r.get("title"), "link": r.get("url"), "snippet": r.get("description")}
        for r in results
        if r.get("url")
    ]
