"""httpx wrapper — alive check + tech fingerprint (module 5)."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from modules.exec import run_tool_jsonl

Runner = Callable[..., Awaitable[list[dict]]]


async def probe(hosts: list[str], timeout: float, *, runner: Runner = run_tool_jsonl) -> list[dict]:
    """Probe hosts and return normalised records for the alive ones.

    Each record: ``{url, host, status_code, title, tech, webserver}``.
    """
    hosts = [h for h in hosts if h]
    if not hosts:
        return []
    rows = await runner(
        "httpx",
        ["-silent", "-json", "-status-code", "-title", "-tech-detect", "-no-color"],
        timeout=timeout,
        stdin="\n".join(hosts),
    )
    results: list[dict] = []
    for r in rows:
        url = r.get("url")
        if not url:
            continue
        results.append(
            {
                "url": url,
                "host": (r.get("input") or r.get("host") or "").lower().rstrip("."),
                "status_code": r.get("status_code") or r.get("status-code"),
                "title": r.get("title"),
                "tech": r.get("tech") or r.get("technologies") or [],
                "webserver": r.get("webserver"),
            }
        )
    return results
