"""crt.sh wrapper — certificate-transparency subdomain discovery (module 2).

Pure HTTP (no binary). The fetch callable is injected so tests run offline.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable

from core.logging import logger

Fetch = Callable[[str], Awaitable[str]]
Sleep = Callable[[float], Awaitable[None]]

#: crt.sh routinely returns an empty body or an HTML 502/rate-limit page under
#: load; a couple of retries turns most of those into a good JSON response.
CRTSH_ATTEMPTS = 3
CRTSH_BACKOFF = 2.0


async def _default_fetch(url: str) -> str:
    import aiohttp

    async with aiohttp.ClientSession() as session:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
            return await resp.text()


async def enumerate_subdomains(
    domain: str,
    *,
    fetch: Fetch = _default_fetch,
    attempts: int = CRTSH_ATTEMPTS,
    sleep: Sleep = asyncio.sleep,
) -> list[str]:
    """Return subdomains of *domain* seen in certificate transparency logs.

    crt.sh is flaky (empty body / HTML error page under load), so a
    non-JSON/failed response is retried with a short backoff. If every attempt
    fails we degrade to an empty list — subfinder + dnsx cover the same ground,
    so a crt.sh outage must never fail ingest — and log at INFO (not WARNING)
    because it is expected, not actionable.
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    rows: list | None = None
    last_exc: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            rows = json.loads(await fetch(url))
            break
        except Exception as exc:  # noqa: BLE001 - crt.sh is flaky; retry then degrade
            last_exc = exc
            if attempt < attempts:
                await sleep(min(CRTSH_BACKOFF * attempt, 5.0))
    if rows is None:
        logger.info(
            "crt.sh unavailable for {} after {} attempt(s) ({}); other sources cover it",
            domain,
            attempts,
            type(last_exc).__name__ if last_exc else "no data",
        )
        return []

    names: set[str] = set()
    for row in rows:
        for raw in (row.get("name_value") or "").split("\n"):
            name = raw.strip().lower().lstrip("*.").rstrip(".")
            if name and (name == domain or name.endswith("." + domain)):
                names.add(name)
    return sorted(names)
