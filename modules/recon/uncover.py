"""uncover wrapper — unified Shodan/Censys/Fofa/Zoomeye search (module 3).

Replaces separate Shodan + Censys wrappers (ADR-0002). uncover reads its API keys from
ENVIRONMENT VARIABLES (SHODAN_API_KEY / CENSYS_API_ID+SECRET / …); the caller passes the
tenant's stored keys in via ``api_env`` so they reach the child process without leaking
into the worker's own environment. Degrades to empty results if a backend is
unconfigured. Returns ``host:port`` strings.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from core.logging import logger
from modules.exec import run_tool

Runner = Callable[[str], Awaitable[list[str]]]

_ENGINE_FLAG = {"shodan": "-shodan", "censys": "-censys", "fofa": "-fofa", "quake": "-quake"}


async def search(
    query: str,
    timeout: float,
    *,
    engine: str = "shodan",
    api_env: dict[str, str] | None = None,
    runner: Runner | None = None,
) -> list[str]:
    """Run *query* against *engine* and return discovered ``host:port`` entries.

    ``api_env`` carries the API-key env vars for the child process. ``runner`` is an
    injected test double taking ``(query)`` and returning host:port lines."""
    if runner is not None:  # tests
        return sorted(set(await runner(query)))

    flag = _ENGINE_FLAG.get(engine, "-shodan")
    run = await run_tool("uncover", [flag, query, "-silent"], timeout=timeout, env=api_env)
    lines = [ln.strip() for ln in run.stdout.splitlines() if ln.strip()]
    if not lines and run.stderr.strip():
        # surface auth/plan problems (bad key, search not on the plan) instead of a silent 0
        logger.warning(
            "uncover {} via {}: no results ({})",
            query,
            engine,
            run.stderr.strip().splitlines()[-1][:200],
        )
    return sorted(set(lines))
