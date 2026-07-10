"""feroxbuster wrapper — recursive directory/file discovery (module 15)."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from modules.content_discovery.wordlist_selector import wordlist_path
from modules.exec import run_tool_jsonl

Runner = Callable[..., Awaitable[list[dict]]]


async def discover(
    url: str, wordlist: str, timeout: float, *, runner: Runner = run_tool_jsonl
) -> list[dict]:
    """Return discovered ``{url, status, content_length}`` entries for *url*.

    The caller passes a logical wordlist *name*; for the real tool we resolve it to
    an absolute path (a bare filename makes feroxbuster fail instantly with no
    output). Injected runners (tests) get the value untouched. content_discovery
    guards up-front that wordlists are installed."""
    if runner is run_tool_jsonl:
        wordlist = wordlist_path(wordlist)
    rows = await runner(
        "feroxbuster",
        ["-u", url, "-w", wordlist, "--json", "-q", "-k", "--no-recursion"],
        timeout=timeout,
    )
    results: list[dict] = []
    for r in rows:
        if r.get("type") == "response" and r.get("url"):
            results.append(
                {
                    "url": r["url"],
                    "status": r.get("status"),
                    "content_length": r.get("content_length"),
                }
            )
    return results
