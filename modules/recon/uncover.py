"""uncover wrapper — unified Shodan/Censys/Fofa/Zoomeye search (module 3).

Replaces separate Shodan + Censys wrappers (ADR-0002). Requires the relevant API
key(s) in the environment; degrades to empty results if a backend is unconfigured.
Returns ``host:port`` strings.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from modules.exec import run_tool_lines

Runner = Callable[..., Awaitable[list[str]]]

_ENGINE_FLAG = {"shodan": "-shodan", "censys": "-censys", "fofa": "-fofa", "quake": "-quake"}


async def search(
    query: str, timeout: float, *, engine: str = "shodan", runner: Runner = run_tool_lines
) -> list[str]:
    """Run *query* against *engine* and return discovered ``host:port`` entries."""
    flag = _ENGINE_FLAG.get(engine, "-shodan")
    lines = await runner("uncover", [flag, query, "-silent"], timeout=timeout)
    return sorted(set(lines))
