"""naabu wrapper — fast-but-polite port discovery (module 11, ADR-0004).

Masscan is disabled in v1; naabu is the port scanner, run with a bounded ``-rate``.
The global politeness limiter still caps total packets per target IP (§3.8b), and
the scope engine only ever permits port scanning against confirmed-dedicated IPs.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from modules.exec import run_tool_jsonl

Runner = Callable[..., Awaitable[list[dict]]]


async def scan_ports(
    hosts: list[str],
    timeout: float,
    *,
    rate: int = 1000,
    top_ports: str = "100",
    runner: Runner = run_tool_jsonl,
) -> list[dict]:
    """Return open ports as ``{ip, host, port, protocol}`` dicts."""
    hosts = [h for h in hosts if h]
    if not hosts:
        return []
    rows = await runner(
        "naabu",
        ["-silent", "-json", "-rate", str(rate), "-top-ports", top_ports],
        timeout=timeout,
        stdin="\n".join(hosts),
    )
    results: list[dict] = []
    for r in rows:
        ip = r.get("ip") or r.get("host")
        port = r.get("port")
        if ip and port:
            results.append(
                {
                    "ip": ip,
                    "host": r.get("host"),
                    "port": int(port),
                    "protocol": r.get("protocol", "tcp"),
                }
            )
    return results
