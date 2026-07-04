"""dnsx wrapper — bulk DNS resolution (module 4) + the scope resolver.

Doubles as the resolver injected into ``core.scope.assert_in_scope``: the worker
resolves a target with :func:`resolve_one` and hands the IPs to the scope engine.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from modules.exec import run_tool_jsonl

Runner = Callable[..., Awaitable[list[dict]]]


async def resolve_hosts(
    hosts: list[str], timeout: float, *, runner: Runner = run_tool_jsonl
) -> dict[str, list[str]]:
    """Resolve many hosts at once → ``{host: [ipv4, ...]}`` (wildcards filtered by dnsx)."""
    hosts = [h for h in hosts if h]
    if not hosts:
        return {}
    rows = await runner(
        "dnsx",
        ["-silent", "-json", "-a", "-resp"],
        timeout=timeout,
        stdin="\n".join(hosts),
    )
    out: dict[str, set[str]] = {}
    for r in rows:
        host = (r.get("host") or "").lower().rstrip(".")
        if not host:
            continue
        out.setdefault(host, set()).update(r.get("a") or [])
    return {h: sorted(ips) for h, ips in out.items()}


async def resolve_one(host: str, timeout: float, *, runner: Runner = run_tool_jsonl) -> list[str]:
    """Resolve a single host (the scope resolver signature: ``(host) -> [ip]``)."""
    resolved = await resolve_hosts([host], timeout, runner=runner)
    return resolved.get(host.lower().rstrip("."), [])
