"""Discord webhook notifier (module 34)."""

from __future__ import annotations

from modules.notification.base import Alert, Senders, severity_color


async def send(alert: Alert, config: dict, senders: Senders) -> bool:
    url = config.get("webhook_url")
    if not url:
        return False
    payload = {
        "embeds": [
            {
                "title": f"[{alert.severity.value.upper()}] {alert.title}",
                "description": alert.detail or alert.location,
                "color": severity_color(alert.severity),
                "fields": [
                    {"name": "Program", "value": alert.program, "inline": True},
                    {"name": "Module", "value": alert.module, "inline": True},
                    {"name": "Location", "value": alert.location, "inline": False},
                ],
            }
        ]
    }
    status = await senders.http(url, payload)
    return 200 <= status < 300
