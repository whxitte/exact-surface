"""Subfinder wrapper — passive subdomain enumeration (module 1)."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from modules.exec import run_tool_jsonl

Runner = Callable[..., Awaitable[list[dict]]]


async def enumerate_subdomains(
    domain: str, timeout: float, *, runner: Runner = run_tool_jsonl
) -> list[str]:
    """Return sorted, de-duplicated subdomains of *domain* discovered passively.

    ``runner`` is injected so tests can supply canned JSONL rows without the binary.
    """
    rows = await runner("subfinder", ["-d", domain, "-silent", "-oJ"], timeout=timeout)
    hosts = {(r.get("host") or "").lower().rstrip(".") for r in rows if r.get("host")}
    return sorted(h for h in hosts if h)
