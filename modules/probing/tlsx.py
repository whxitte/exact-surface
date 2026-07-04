"""tlsx wrapper — TLS cert inspection + SAN harvest (module 6).

Doubles as a recon source: Subject Alternative Names often reveal additional
in-scope hostnames.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from modules.exec import run_tool_jsonl

Runner = Callable[..., Awaitable[list[dict]]]


async def inspect(
    hosts: list[str], timeout: float, *, runner: Runner = run_tool_jsonl
) -> list[dict]:
    """Return cert details per host: ``{host, cn, sans, not_after, expired}``."""
    hosts = [h for h in hosts if h]
    if not hosts:
        return []
    rows = await runner(
        "tlsx",
        ["-json", "-silent", "-san", "-cn", "-expired", "-so"],
        timeout=timeout,
        stdin="\n".join(hosts),
    )
    results: list[dict] = []
    for r in rows:
        results.append(
            {
                "host": (r.get("host") or "").lower().rstrip("."),
                "cn": r.get("subject_cn"),
                "sans": r.get("subject_an") or [],
                "not_after": r.get("not_after"),
                "expired": bool(r.get("expired", False)),
            }
        )
    return results
