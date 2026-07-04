"""Google Programmable Search (CSE) wrapper (module 18).

Injectable fetch for offline tests; degrades to empty if the CSE key/cx is unset.
Returns ``{title, link, snippet}`` items.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

Fetch = Callable[[str], Awaitable[dict]]


async def _default_fetch(url: str) -> dict:  # pragma: no cover - needs API keys
    import aiohttp

    async with aiohttp.ClientSession() as session:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=20)) as resp:
            return await resp.json(content_type=None)


async def search(
    query: str, *, key: str | None = None, cx: str | None = None, fetch: Fetch = _default_fetch
) -> list[dict]:
    if not key or not cx:
        return []
    from urllib.parse import quote_plus

    url = f"https://www.googleapis.com/customsearch/v1?key={key}&cx={cx}&q={quote_plus(query)}"
    data = await fetch(url)
    return [
        {"title": it.get("title"), "link": it.get("link"), "snippet": it.get("snippet")}
        for it in data.get("items", [])
        if it.get("link")
    ]
