"""httpx wrapper — alive check + tech fingerprint (module 5).

``-rl`` is the only politeness control that applies: httpx is a subprocess sending
its own requests, so the token bucket in ``core.ratelimit`` never sees them. Its
own default is **150 rps**, 15x the §3.8b cap, and this wrapper passed no rate flag
at all until ADR-0013. Callers derive the rate from the per-target cap via
``core.ratelimit.derive_subprocess_rate``; the default below is a fallback for
direct/manual use, not a policy.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from modules.exec import run_tool_jsonl

Runner = Callable[..., Awaitable[list[dict]]]

#: httpx's own default is 150 rps. This is not it.
DEFAULT_RATE = 10


async def probe(
    hosts: list[str],
    timeout: float,
    *,
    rate: int = DEFAULT_RATE,
    runner: Runner = run_tool_jsonl,
) -> list[dict]:
    """Probe hosts and return normalised records for the alive ones.

    Each record: ``{url, host, status_code, title, tech, webserver}``.
    """
    hosts = [h for h in hosts if h]
    if not hosts:
        return []
    rows = await runner(
        "httpx",
        [
            "-silent",
            "-json",
            "-status-code",
            "-title",
            "-tech-detect",
            "-no-color",
            "-rl",
            str(rate),
        ],
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
