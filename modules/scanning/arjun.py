"""arjun wrapper — hidden parameter discovery (module: param_discovery).

arjun (s0md3v, MIT-licensed, free) is the tool bug hunters actually use for this, and
it is better at it than a hand-rolled prober: it maintains a large parameter wordlist,
handles chunked binary search, and knows how to tell a real behavioural change from a
page that simply renders differently each time.

It is the **primary** engine. ``modules.scanning.params`` stays as the always-on
fallback, exactly like trufflehog and the regex secret detector: if arjun is missing
from the image, parameter discovery degrades to the built-in curated probe rather than
producing nothing. A missing tool must never look like a clean result.

Nothing here is paid. arjun is free software, and no module in this product requires a
commercial data source to function — see docs/DEVTOOLS.md and the README's module table
for the handful of optional modules that can *use* a key if you have one.
"""

from __future__ import annotations

import json
import tempfile
from collections.abc import Awaitable, Callable
from pathlib import Path

from core.errors import ToolNotFound
from core.logging import logger
from modules.exec import run_tool

Runner = Callable[..., Awaitable[tuple]]

#: Cap arjun's own concurrency. Its default is aggressive for a tool we run unattended
#: against someone's production site, and the politeness limiter cannot see inside it.
DEFAULT_THREADS = 5
#: Delay between arjun's requests, in seconds. Same reasoning.
DEFAULT_DELAY = 0.2
#: How many URLs to hand a single invocation.
MAX_URLS = 50


async def find_params(
    urls: list[str],
    timeout: float,
    *,
    threads: int = DEFAULT_THREADS,
    delay: float = DEFAULT_DELAY,
    runner: Runner = run_tool,
) -> dict[str, list[str]]:
    """``{url: [param, ...]}`` for each URL arjun found hidden parameters on.

    Returns ``{}`` — not an exception — when arjun is not installed, so the caller can
    fall back. Every other failure is also swallowed into ``{}`` for the same reason:
    this is one signal among several, not the stage.
    """
    urls = [u for u in urls if u][:MAX_URLS]
    if not urls:
        return {}

    with tempfile.TemporaryDirectory() as tmp:
        in_path = Path(tmp) / "urls.txt"
        out_path = Path(tmp) / "out.json"
        in_path.write_text("\n".join(urls))

        args = [
            "-i", str(in_path),
            "-oJ", str(out_path),
            "-t", str(threads),
            "-d", str(delay),
            "--stable",  # compare against a stable baseline rather than one sample
            "-q",
        ]
        try:
            await runner("arjun", args, timeout=timeout, check=False)
        except ToolNotFound:
            logger.info("arjun not installed — falling back to the built-in parameter probe")
            return {}
        except Exception as exc:  # noqa: BLE001 - one tool never sinks the stage
            logger.warning("arjun failed ({}); falling back to the built-in probe", exc)
            return {}

        if not out_path.exists():
            return {}
        try:
            data = json.loads(out_path.read_text() or "{}")
        except ValueError:
            logger.warning("arjun produced unparseable output; ignoring it")
            return {}

    return _normalise(data)


def _normalise(data: object) -> dict[str, list[str]]:
    """arjun's JSON is ``{url: {"params": [...], ...}}``, but the exact shape has moved
    between releases. Accept both the nested and the flat form rather than pinning to
    one and silently returning nothing after an upgrade."""
    out: dict[str, list[str]] = {}
    if not isinstance(data, dict):
        return out
    for url, value in data.items():
        if not isinstance(url, str):
            continue
        params: list[str] = []
        if isinstance(value, dict):
            found = value.get("params") or value.get("parameters") or []
            if isinstance(found, dict):
                params = [str(k) for k in found]
            elif isinstance(found, list):
                params = [str(p) for p in found]
        elif isinstance(value, list):
            params = [str(p) for p in value]
        if params:
            out[url] = sorted(set(params))
    return out
