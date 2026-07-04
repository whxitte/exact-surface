"""ffuf wrapper — parameter / vhost fuzzing (module 16).

ffuf emits a single JSON object (``-of json``) rather than JSONL, so we parse the
whole blob. The ``FUZZ`` keyword marks the injection point in the URL.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable

from modules.exec import run_tool_stdout

Runner = Callable[..., Awaitable[str]]


async def fuzz(
    url: str, wordlist: str, timeout: float, *, runner: Runner = run_tool_stdout
) -> list[dict]:
    """Fuzz ``FUZZ`` in *url* and return ``{url, status, length}`` hits."""
    out = await runner(
        "ffuf",
        ["-u", url, "-w", wordlist, "-of", "json", "-o", "-", "-s"],
        timeout=timeout,
    )
    try:
        payload = json.loads(out) if out.strip() else {}
    except json.JSONDecodeError:
        return []
    results: list[dict] = []
    for r in payload.get("results", []):
        results.append({"url": r.get("url"), "status": r.get("status"), "length": r.get("length")})
    return results
