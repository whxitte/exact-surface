"""uncover wrapper — unified Shodan/Censys/Fofa/Zoomeye search (module 3).

Replaces separate Shodan + Censys wrappers (ADR-0002). uncover reads its API keys from
ENVIRONMENT VARIABLES (SHODAN_API_KEY / CENSYS_API_ID+SECRET / …); the caller passes the
tenant's stored keys in via ``api_env`` so they reach the child process without leaking
into the worker's own environment.

Output is parsed from ``-json`` so each result carries BOTH the ``ip`` and the ``host``
(hostname when the engine has one) — the hostname is what lets an in-scope subdomain
become an asset even when its IP is a shared CDN edge. Degrades to empty on a missing
key/binary; auth/plan errors are logged, never raised.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable

from core.logging import logger
from modules.exec import run_tool

Runner = Callable[[str], Awaitable[list[dict]]]

_ENGINE_FLAG = {"shodan": "-shodan", "censys": "-censys", "fofa": "-fofa", "quake": "-quake"}


async def search(
    query: str,
    timeout: float,
    *,
    engine: str = "shodan",
    api_env: dict[str, str] | None = None,
    runner: Runner | None = None,
) -> list[dict]:
    """Run *query* against *engine* and return ``[{host, ip, port}, …]``.

    ``api_env`` carries the API-key env vars for the child process. ``runner`` is an
    injected test double taking ``(query)`` and returning the same shape."""
    if runner is not None:  # tests
        return await runner(query)

    flag = _ENGINE_FLAG.get(engine, "-shodan")
    run = await run_tool("uncover", [flag, query, "-json", "-silent"], timeout=timeout, env=api_env)
    results: list[dict] = []
    for line in run.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        ip = str(obj.get("ip") or "")
        host = str(obj.get("host") or ip).lower().rstrip(".")
        port = obj.get("port")
        if port is None:
            continue
        results.append({"host": host, "ip": ip, "port": int(port)})
    if not results and run.stderr.strip():
        # surface auth/plan problems (bad key, search not on the plan) instead of a silent 0
        logger.warning(
            "uncover {} via {}: no results ({})",
            query,
            engine,
            run.stderr.strip().splitlines()[-1][:200],
        )
    return results
