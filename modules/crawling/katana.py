"""Katana wrapper — deep active endpoint discovery (module 9).

``-rl`` is the only politeness control that applies: katana is a subprocess sending
its own requests, so the token bucket in ``core.ratelimit`` never sees them. Its own
default is **150 rps**, 15x the §3.8b cap, and this wrapper passed no rate flag at
all until ADR-0013. A crawl is also the single most request-hungry thing we do to
one host — it walks the whole site.

Each invocation targets ONE url, so the per-target rate *is* the rate: callers pass
the cap itself, not an aggregate (contrast naabu, which is handed many hosts at once).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from modules.exec import run_tool_jsonl

Runner = Callable[..., Awaitable[list[dict]]]

#: katana's own default is 150 rps. This is not it.
DEFAULT_RATE = 10


async def crawl(
    url: str,
    timeout: float,
    *,
    depth: int = 2,
    rate: int = DEFAULT_RATE,
    runner: Runner = run_tool_jsonl,
) -> list[str]:
    """Crawl *url* and return discovered endpoint URLs (active — needs HTTP_PROBE)."""
    rows = await runner(
        "katana",
        ["-u", url, "-jsonl", "-silent", "-d", str(depth), "-nc", "-rl", str(rate)],
        timeout=timeout,
    )
    urls: set[str] = set()
    for r in rows:
        endpoint = r.get("endpoint") or r.get("url") or (r.get("request") or {}).get("endpoint")
        if endpoint:
            urls.add(endpoint)
    return sorted(urls)
