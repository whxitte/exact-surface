"""SerpAPI wrapper (module 20) — Google results via a paid proxy.

Same ``{title, link, snippet}`` shape as the Google CSE and Brave wrappers.
Injectable fetch for offline tests; no key → no results.

SerpAPI is metered per search, so §13 budgeting applies once commercial metering
lands — it is deliberately the *last* engine tried in the dork pipeline.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from urllib.parse import quote_plus

Fetch = Callable[[str], Awaitable[dict]]

_ENDPOINT = "https://serpapi.com/search.json"


async def _default_fetch(url: str) -> dict:  # pragma: no cover - needs an API key
    import aiohttp

    async with aiohttp.ClientSession() as session:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=20)) as resp:
            return await resp.json(content_type=None)


async def search(
    query: str, *, key: str | None = None, fetch: Fetch = _default_fetch
) -> list[dict]:
    if not key:
        return []
    url = f"{_ENDPOINT}?engine=google&q={quote_plus(query)}&api_key={quote_plus(key)}"
    data = await fetch(url)
    return [
        {"title": r.get("title"), "link": r.get("link"), "snippet": r.get("snippet")}
        for r in data.get("organic_results") or []
        if r.get("link")
    ]
