"""gau wrapper — historical URL harvest (module 10, passive)."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from modules.exec import run_tool_lines

Runner = Callable[..., Awaitable[list[str]]]


async def fetch_urls(domain: str, timeout: float, *, runner: Runner = run_tool_lines) -> list[str]:
    """Return archived URLs for *domain* (and its subdomains)."""
    lines = await runner("gau", ["--subs", "--threads", "5"], timeout=timeout, stdin=domain)
    return sorted(set(lines))
