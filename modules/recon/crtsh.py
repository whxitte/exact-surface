"""crt.sh wrapper — certificate-transparency subdomain discovery (module 2).

Pure HTTP (no binary). The fetch callable is injected so tests run offline.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable

from core.logging import logger

Fetch = Callable[[str], Awaitable[str]]


async def _default_fetch(url: str) -> str:
    import aiohttp

    async with aiohttp.ClientSession() as session:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
            return await resp.text()


async def enumerate_subdomains(domain: str, *, fetch: Fetch = _default_fetch) -> list[str]:
    """Return subdomains of *domain* seen in certificate transparency logs."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        text = await fetch(url)
        rows = json.loads(text)
    except Exception as exc:  # noqa: BLE001 - crt.sh is flaky; degrade, don't fail ingest
        logger.warning("crt.sh lookup failed for {}: {}", domain, exc)
        return []

    names: set[str] = set()
    for row in rows:
        for raw in (row.get("name_value") or "").split("\n"):
            name = raw.strip().lower().lstrip("*.").rstrip(".")
            if name and (name == domain or name.endswith("." + domain)):
                names.add(name)
    return sorted(names)
