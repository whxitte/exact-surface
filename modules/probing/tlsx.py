"""tlsx wrapper — TLS cert inspection + SAN harvest (module 6).

Doubles as a recon source: Subject Alternative Names often reveal additional
in-scope hostnames.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime

from modules.exec import run_tool_jsonl

Runner = Callable[..., Awaitable[list[dict]]]


def _is_expired(not_after: str | None) -> bool:
    """True if the cert's ``not_after`` is in the past. Tolerates date-only and
    RFC3339 forms; unparseable → not expired (don't flag on bad data)."""
    if not not_after:
        return False
    try:
        dt = datetime.fromisoformat(str(not_after).replace("Z", "+00:00"))
    except ValueError:
        return False
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt < datetime.now(UTC)


async def inspect(
    hosts: list[str], timeout: float, *, runner: Runner = run_tool_jsonl
) -> list[dict]:
    """Return cert details per host: ``{host, cn, sans, not_after, expired}``.

    Uses minimal flags (``-json -silent``): with ``-json`` tlsx emits the full cert
    object (CN, SANs, not_after) regardless of the text display flags, and expiry is
    computed from ``not_after`` here rather than depending on a display-only flag
    (the previous ``-so`` flag made tlsx emit nothing → "0 cert(s) inspected")."""
    hosts = [h for h in hosts if h]
    if not hosts:
        return []
    rows = await runner(
        "tlsx",
        ["-json", "-silent"],
        timeout=timeout,
        stdin="\n".join(hosts),
    )
    results: list[dict] = []
    for r in rows:
        not_after = r.get("not_after")
        results.append(
            {
                "host": (r.get("host") or "").lower().rstrip("."),
                "cn": r.get("subject_cn"),
                "sans": r.get("subject_an") or [],
                "not_after": not_after,
                "expired": bool(r.get("expired", False)) or _is_expired(not_after),
            }
        )
    return results
