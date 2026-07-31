"""dnsx wrapper — bulk DNS resolution (module 4) + the scope resolver.

Doubles as the resolver injected into ``core.scope.assert_in_scope``: the worker
resolves a target with :func:`resolve_one` and hands the IPs to the scope engine.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from core.errors import ToolNotFound
from modules.exec import run_tool_jsonl

Runner = Callable[..., Awaitable[list[dict]]]

#: DNS record types we enrich each asset with (dnsx -recon style).
DNS_RECORD_KEYS: tuple[str, ...] = ("a", "aaaa", "cname", "ns", "mx", "txt")


async def recon_hosts(
    hosts: list[str], timeout: float, *, runner: Runner = run_tool_jsonl
) -> dict[str, dict[str, list[str]]]:
    """Full DNS records per host (A/AAAA/CNAME/NS/MX/TXT) for attack-surface mapping.

    Best-effort enrichment: if dnsx isn't available it returns ``{}`` rather than
    failing the run. Shape: ``{host: {"cname": [...], "mx": [...], ...}}`` (only
    record types that have values are included)."""
    hosts = [h for h in hosts if h]
    if not hosts:
        return {}
    try:
        rows = await runner(
            "dnsx",
            ["-silent", "-json", "-a", "-aaaa", "-cname", "-ns", "-mx", "-txt", "-resp"],
            timeout=timeout,
            stdin="\n".join(hosts),
        )
    except ToolNotFound:
        return {}

    out: dict[str, dict[str, set[str]]] = {}
    for r in rows:
        host = (r.get("host") or "").lower().rstrip(".")
        if not host:
            continue
        rec = out.setdefault(host, {k: set() for k in DNS_RECORD_KEYS})
        for key in DNS_RECORD_KEYS:
            vals = r.get(key) or []
            if isinstance(vals, str):
                vals = [vals]
            rec[key].update(str(v) for v in vals if v)
    return {
        host: {k: sorted(v) for k, v in rec.items() if v} for host, rec in out.items()
    }


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


async def resolve_mx_hosts(
    hosts: list[str], timeout: float, *, runner: Runner = run_tool_jsonl
) -> dict[str, list[str]]:
    """MX records for many hosts at once → ``{host: [exchange, ...]}``.

    Batched deliberately: the typosquat stage checks hundreds of candidate domains, and
    one dnsx invocation over a host list is both far faster and far gentler on
    resolvers than a lookup per name.
    """
    hosts = [h for h in hosts if h]
    if not hosts:
        return {}
    rows = await runner(
        "dnsx",
        ["-silent", "-json", "-mx", "-resp"],
        timeout=timeout,
        stdin="\n".join(hosts),
    )
    out: dict[str, set[str]] = {}
    for r in rows:
        host = (r.get("host") or "").lower().rstrip(".")
        if not host:
            continue
        out.setdefault(host, set()).update(str(m) for m in (r.get("mx") or []))
    return {h: sorted(v) for h, v in out.items()}


async def resolve_txt_records(
    hostname: str, timeout: float = 20.0, *, runner: Runner = run_tool_jsonl
) -> list[str]:
    """TXT records for one hostname. Used for SPF/DMARC/DKIM assessment, where the
    interesting names are ``_dmarc.<domain>`` and ``<selector>._domainkey.<domain>``
    rather than the hosts we already resolve during ingest."""
    rows = await runner(
        "dnsx",
        ["-silent", "-json", "-txt", "-resp"],
        timeout=timeout,
        stdin=hostname,
    )
    out: list[str] = []
    for r in rows:
        for value in r.get("txt") or []:
            cleaned = str(value).strip().strip('"')
            if cleaned:
                out.append(cleaned)
    return out
