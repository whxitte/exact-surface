"""GitHub leaked-secret monitoring (module 21/OSINT).

Searches public GitHub code for the customer's domain and scans the matched
fragments for secrets using the shared detector. The GitHub search callable is
injected so tests run offline; in production it wraps the GitHub code-search API
(auth required, heavily rate-limited — budget per §3.8/§13).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from core.logging import logger
from core.secrets_policy import find_secrets

Search = Callable[[str], Awaitable[list[dict]]]


def _make_search(token: str) -> Search:  # pragma: no cover - needs a token
    async def _search(query: str) -> list[dict]:
        import aiohttp

        # The `text-match` media type is REQUIRED to get `text_matches` back — without
        # it GitHub returns items with no code fragments, so the secret detector has
        # nothing to scan and every search silently yields zero leaks.
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github.text-match+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        params = {"q": query, "per_page": "50"}
        async with aiohttp.ClientSession(headers=headers) as session:
            async with session.get(
                "https://api.github.com/search/code",
                params=params,
                timeout=aiohttp.ClientTimeout(total=30),
            ) as resp:
                data = await resp.json()
                if resp.status != 200:
                    logger.warning(
                        "github code-search {} failed: HTTP {} — {}",
                        query,
                        resp.status,
                        (data or {}).get("message", ""),
                    )
                    return []
        items = []
        for it in data.get("items", []):
            fragment = " ".join(tm.get("fragment", "") for tm in it.get("text_matches", []))
            items.append(
                {
                    "repo": (it.get("repository") or {}).get("full_name"),
                    "path": it.get("path"),
                    "html_url": it.get("html_url"),
                    "content": fragment,
                }
            )
        return items

    return _search


async def search_leaks(
    domain: str, *, search: Search | None = None, token: str | None = None
) -> list[dict]:
    """Return leaked-secret hits referencing *domain* in public GitHub code.

    Pass an explicit *search* (tests) or a *token* to build the authenticated
    GitHub code-search client; with neither, there is nothing to query."""
    if search is None:
        if not token:
            return []
        search = _make_search(token)

    # A handful of targeted queries — the bare domain plus common secret keywords —
    # deduped by result URL. GitHub code-search is rate-limited (~10 req/min), so the
    # set is deliberately small.
    queries = [
        f'"{domain}"',
        f'"{domain}" password',
        f'"{domain}" api_key',
        f'"{domain}" secret',
    ]
    seen_urls: set[str] = set()
    hits: list[dict] = []
    logger.info("github-osint: {} search quer(ies) crafted for {}", len(queries), domain)
    for query in queries:
        # Show the EXACT query, so the user can reproduce the search themselves — the
        # same transparency rule the dork module follows.
        results = await search(query)
        # This is GitHub's raw text-match count -- a file that merely MENTIONS the
        # domain (a README, a CORS allow-list, a changelog entry). Each one still gets
        # run through find_secrets() below; only a real credential-shaped string in
        # the content becomes a hit. Logged as "match(es)", never "result(s)"/"hit(s)",
        # so this reads as what it is instead of implying secrets were found here.
        logger.info("github-osint: searching {} → {} code match(es)", query, len(results))
        for item in results:
            url = item.get("html_url", "")
            if url in seen_urls:
                continue
            seen_urls.add(url)
            for secret in find_secrets(item.get("content", ""), url):
                hits.append(
                    {
                        "repo": item.get("repo"),
                        "file_path": item.get("path"),
                        "url": url,
                        **secret,
                    }
                )
    return hits
