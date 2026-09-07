"""ASN mapper (module 22) — org/domain → ASN → owned IP ranges.

Feeds the authorization IP-scope confirmation (§9b): a resolved IP that falls in a
range genuinely owned by the operator's ASN can be promoted to DEDICATED (full
scanning). Wraps ``asnmap``; runner injected for offline tests.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from modules.exec import run_tool_jsonl

Runner = Callable[..., Awaitable[list[dict]]]


async def map_domain(domain: str, timeout: float, *, runner: Runner = run_tool_jsonl) -> list[str]:
    """Return the CIDR ranges announced by the ASN(s) behind *domain*."""
    rows = await runner("asnmap", ["-d", domain, "-json", "-silent"], timeout=timeout)
    cidrs: set[str] = set()
    for r in rows:
        for cidr in r.get("as_range") or []:
            cidrs.add(cidr)
    return sorted(cidrs)
