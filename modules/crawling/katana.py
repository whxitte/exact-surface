"""Katana wrapper — deep active endpoint discovery (module 9)."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from modules.exec import run_tool_jsonl

Runner = Callable[..., Awaitable[list[dict]]]


async def crawl(
    url: str, timeout: float, *, depth: int = 2, runner: Runner = run_tool_jsonl
) -> list[str]:
    """Crawl *url* and return discovered endpoint URLs (active — needs HTTP_PROBE)."""
    rows = await runner(
        "katana",
        ["-u", url, "-jsonl", "-silent", "-d", str(depth), "-nc"],
        timeout=timeout,
    )
    urls: set[str] = set()
    for r in rows:
        endpoint = r.get("endpoint") or r.get("url") or (r.get("request") or {}).get("endpoint")
        if endpoint:
            urls.add(endpoint)
    return sorted(urls)
