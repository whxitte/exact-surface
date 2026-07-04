"""Slack incoming-webhook notifier (module 36)."""

from __future__ import annotations

from modules.notification.base import Alert, Senders, severity_color


async def send(alert: Alert, config: dict, senders: Senders) -> bool:
    url = config.get("webhook_url")
    if not url:
        return False
    payload = {
        "attachments": [
            {
                "color": f"#{severity_color(alert.severity):06x}",
                "title": f"[{alert.severity.value.upper()}] {alert.title}",
                "text": alert.detail or alert.location,
                "fields": [
                    {"title": "Program", "value": alert.program, "short": True},
                    {"title": "Module", "value": alert.module, "short": True},
                    {"title": "Location", "value": alert.location, "short": False},
                ],
            }
        ]
    }
    status = await senders.http(url, payload)
    return 200 <= status < 300
