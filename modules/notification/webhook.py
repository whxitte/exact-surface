"""Generic HTTP webhook notifier (module 38) — POSTs the alert as JSON."""

from __future__ import annotations

from modules.notification.base import Alert, Senders


async def send(alert: Alert, config: dict, senders: Senders) -> bool:
    url = config.get("url")
    if not url:
        return False
    payload = {
        "title": alert.title,
        "severity": alert.severity.value,
        "program": alert.program,
        "location": alert.location,
        "module": alert.module,
        "detail": alert.detail,
        "reference": alert.reference,
    }
    status = await senders.http(url, payload)
    return 200 <= status < 300
