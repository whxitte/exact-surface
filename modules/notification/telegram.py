"""Telegram bot notifier (module 35)."""

from __future__ import annotations

from modules.notification.base import Alert, Senders


async def send(alert: Alert, config: dict, senders: Senders) -> bool:
    token = config.get("bot_token")
    chat_id = config.get("chat_id")
    if not token or not chat_id:
        return False
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {"chat_id": chat_id, "text": alert.text(), "disable_web_page_preview": True}
    status = await senders.http(url, payload)
    return 200 <= status < 300
