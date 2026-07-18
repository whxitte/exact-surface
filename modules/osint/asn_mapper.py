"""ASN mapper (module 22) — org/domain → ASN → owned IP ranges.

Feeds the authorization IP-scope confirmation (§9b): a resolved IP that falls in a
range genuinely owned by the customer's ASN can be promoted to DEDICATED (full
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


async def map_org(org: str, timeout: float, *, runner: Runner = run_tool_jsonl) -> list[str]:
    """Return the CIDR ranges announced by an organisation name.

    Available but **not yet wired** into the pipeline: only :func:`map_domain` feeds
    the §9b IP-scope confirmation today. This is the intended fallback for a
    CDN-fronted apex whose real origin ASN a domain lookup can't reach (the
    limitation noted in ADR-0008) — wire it there deliberately, not incidentally,
    since it gates DEDICATED (full-scan) promotion.
    """
    rows = await runner("asnmap", ["-org", org, "-json", "-silent"], timeout=timeout)
    cidrs: set[str] = set()
    for r in rows:
        for cidr in r.get("as_range") or []:
            cidrs.add(cidr)
    return sorted(cidrs)
