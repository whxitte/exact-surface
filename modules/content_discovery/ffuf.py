"""ffuf wrapper — parameter / vhost fuzzing (module 16).

ffuf emits a single JSON object (``-of json``) rather than JSONL, so we parse the
whole blob. The ``FUZZ`` keyword marks the injection point in the URL.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable

from modules.exec import run_tool_stdout

Runner = Callable[..., Awaitable[str]]

#: ffuf's `-rate` default is 0 = unlimited. This is not that (§3.8b, ADR-0013).
DEFAULT_RATE = 10


async def fuzz(
    url: str,
    wordlist: str,
    timeout: float,
    *,
    rate: int = DEFAULT_RATE,
    runner: Runner = run_tool_stdout,
) -> list[dict]:
    """Fuzz ``FUZZ`` in *url* and return ``{url, status, length}`` hits.

    ``-rate`` defaults to 0 (unlimited) in ffuf and was never passed here: like
    feroxbuster, this empties a wordlist at the host as fast as it answers. It is a
    subprocess, so the token bucket cannot see it — the cap is handed over up front
    (ADR-0013).
    """
    args = ["-u", url, "-w", wordlist, "-of", "json", "-o", "-", "-s", "-rate", str(rate)]
    if runner is run_tool_stdout:  # real tool: a bare wordlist name fails; resolve + bound
        from modules.content_discovery.wordlist_selector import wordlist_path

        args[3] = wordlist_path(wordlist)  # the -w value
        args += ["-maxtime", str(max(int(timeout), 1))]
    out = await runner("ffuf", args, timeout=timeout + 15)
    try:
        payload = json.loads(out) if out.strip() else {}
    except json.JSONDecodeError:
        return []
    results: list[dict] = []
    for r in payload.get("results", []):
        results.append({"url": r.get("url"), "status": r.get("status"), "length": r.get("length")})
    return results
