"""GitHub leaked-secret monitoring (module 21/OSINT).

Searches public GitHub code for the customer's domain and scans the matched
fragments for secrets using the shared detector. The GitHub search callable is
injected so tests run offline; in production it wraps the GitHub code-search API
(auth required, heavily rate-limited — budget per §3.8/§13).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from core.secrets_policy import find_secrets

Search = Callable[[str], Awaitable[list[dict]]]


async def _default_search(query: str) -> list[dict]:  # pragma: no cover - needs a token
    from core.config import get_settings

    token = get_settings().github_token
    if token is None:
        return []
    import aiohttp

    headers = {
        "Authorization": f"Bearer {token.get_secret_value()}",
        "Accept": "application/vnd.github+json",
    }
    url = f"https://api.github.com/search/code?q={query}"
    async with aiohttp.ClientSession(headers=headers) as session:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
            data = await resp.json()
    items = []
    for it in data.get("items", []):
        fragment = " ".join(
            m.get("fragment", "") for tm in it.get("text_matches", []) for m in [tm]
        )
        items.append(
            {
                "repo": (it.get("repository") or {}).get("full_name"),
                "path": it.get("path"),
                "html_url": it.get("html_url"),
                "content": fragment,
            }
        )
    return items


async def search_leaks(domain: str, *, search: Search = _default_search) -> list[dict]:
    """Return leaked-secret hits referencing *domain* in public GitHub code."""
    items = await search(f'"{domain}"')
    hits: list[dict] = []
    for item in items:
        for secret in find_secrets(item.get("content", ""), item.get("html_url", "")):
            hits.append(
                {
                    "repo": item.get("repo"),
                    "file_path": item.get("path"),
                    "url": item.get("html_url"),
                    **secret,
                }
            )
    return hits
