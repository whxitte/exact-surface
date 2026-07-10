"""Attack-surface change analytics (state-aware history).

Every observation carries ``first_seen`` / ``last_seen`` (§3.1 state-awareness), so
an item is "present" on the surface across the interval ``[first_seen, last_seen]``.
That single idea gives us everything the change view needs:

* **present at time T** — ``first_seen <= T <= last_seen``; count it across scan
  points and you get the surface size *over time* (a real trend line).
* **resolved** — an item whose ``last_seen`` predates the latest full scan wasn't
  re-observed, i.e. it closed (port shut, dir removed, finding fixed). ``last_seen``
  is its close time.
* **opened / closed since the last scan** — first_seen / resolved-at falling in the
  most recent scan window.

This module is pure (takes already-loaded docs + scan timestamps, returns plain
dicts) so it is trivially testable without a DB.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

SEVERITY_ORDER: tuple[str, ...] = ("critical", "high", "medium", "low", "info")

#: surface categories: key -> (singular label, label builder, carries severity?)
_TYPES: dict[str, tuple[str, Callable[[dict], str], bool]] = {
    "assets": ("asset", lambda d: d.get("hostname", "?"), False),
    "endpoints": ("endpoint", lambda d: d.get("url", "?"), False),
    "ports": (
        "port",
        lambda d: f"{d.get('ip', '?')}:{d.get('port', '?')}/{d.get('protocol', 'tcp')}",
        False,
    ),
    "findings": ("finding", lambda d: d.get("name") or d.get("check_id", "?"), True),
    "secrets": (
        "secret",
        lambda d: f"{d.get('kind', 'secret')} {d.get('masked', '')}".strip(),
        True,
    ),
    "leaks": (
        "leak",
        lambda d: f"{d.get('kind', 'leak')} · {d.get('repo') or d.get('source', 'public')}",
        True,
    ),
}


def _aware(value: Any) -> datetime | None:
    """Coerce a stored timestamp (datetime or ISO string) to an aware UTC datetime."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
        except ValueError:
            return None
    return None


def _norm(doc: dict) -> dict:
    return {
        "fs": _aware(doc.get("first_seen")),
        "ls": _aware(doc.get("last_seen")),
        "sev": (doc.get("severity") or "info"),
        "doc": doc,
    }


def compute_attack_surface(
    *,
    items_by_type: dict[str, list[dict]],
    scan_points: list[datetime],
    reference: datetime | None,
    now: datetime | None = None,
    grace_seconds: int = 60,
    recent_limit: int = 40,
) -> dict:
    """Summarise the attack surface: current active counts, change since the last
    scan, a surface-size time series, and a recent opened/closed change log."""
    now = now or datetime.now(UTC)
    points = sorted(p for p in scan_points if p is not None)
    latest = points[-1] if points else None
    prev = points[-2] if len(points) >= 2 else None
    cutoff = (reference - timedelta(seconds=grace_seconds)) if reference else None

    norm_by_type = {k: [_norm(d) for d in items_by_type.get(k, [])] for k in _TYPES}

    def _resolved(it: dict) -> bool:
        return bool(cutoff and it["ls"] and it["ls"] < cutoff)

    # -- current (active = still present) -----------------------------------
    current: dict[str, Any] = {}
    total_active = 0
    for key in _TYPES:
        active = [it for it in norm_by_type[key] if not _resolved(it)]
        total_active += len(active)
        _, _, has_sev = _TYPES[key]
        if has_sev:
            by_sev = {s: 0 for s in SEVERITY_ORDER}
            for it in active:
                by_sev[it["sev"]] = by_sev.get(it["sev"], 0) + 1
            current[key] = {"total": len(active), **by_sev}
        else:
            current[key] = {"total": len(active)}
    current["total"] = total_active

    # -- change since the previous scan point -------------------------------
    def _opened_since(it: dict) -> bool:
        # appeared strictly after the previous scan point (i.e. new at the latest scan)
        return bool(it["fs"] and (prev is None or it["fs"] > prev))

    def _resolved_since(it: dict) -> bool:
        # present at the previous scan (last_seen at/after it) but gone now → closed
        return bool(_resolved(it) and it["ls"] and (prev is None or it["ls"] >= prev))

    change: dict[str, Any] = {}
    opened_total = resolved_total = 0
    for key in _TYPES:
        opened = sum(1 for it in norm_by_type[key] if _opened_since(it))
        closed = sum(1 for it in norm_by_type[key] if _resolved_since(it))
        opened_total += opened
        resolved_total += closed
        change[key] = {"opened": opened, "resolved": closed}
    change["opened"] = opened_total
    change["resolved"] = resolved_total
    change["net"] = opened_total - resolved_total

    # -- series: surface size at each scan point ----------------------------
    series = []
    for p in points:
        row: dict[str, Any] = {"at": p.isoformat(), "total": 0}
        for key in _TYPES:
            n = sum(
                1
                for it in norm_by_type[key]
                if it["fs"] and it["fs"] <= p and (it["ls"] is None or it["ls"] >= p)
            )
            row[key] = n
            row["total"] += n
        series.append(row)

    # -- recent change events (opened + closed), newest first ---------------
    events: list[dict] = []
    for key, (singular, label_of, has_sev) in _TYPES.items():
        for it in norm_by_type[key]:
            if _opened_since(it) and it["fs"]:
                events.append(
                    {
                        "kind": "opened",
                        "type": singular,
                        "label": label_of(it["doc"]),
                        "at": it["fs"].isoformat(),
                        "severity": it["sev"] if has_sev else None,
                    }
                )
            if _resolved_since(it) and it["ls"]:
                events.append(
                    {
                        "kind": "resolved",
                        "type": singular,
                        "label": label_of(it["doc"]),
                        "at": it["ls"].isoformat(),
                        "severity": it["sev"] if has_sev else None,
                    }
                )
    events.sort(key=lambda e: e["at"], reverse=True)

    return {
        "generated_at": now.isoformat(),
        "latest_scan_at": latest.isoformat() if latest else None,
        "previous_scan_at": prev.isoformat() if prev else None,
        "scan_count": len(points),
        "current": current,
        "change": change,
        "series": series,
        "recent": events[:recent_limit],
    }
