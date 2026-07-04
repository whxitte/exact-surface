"""SMTP email notifier (module 37).

Delivery goes through the injected ``senders.smtp`` callable so the module has no
hard smtplib dependency and is testable offline. The default SMTP sender (built in
the pipeline for production) sends via ``aiosmtplib``/``smtplib``.
"""

from __future__ import annotations

from modules.notification.base import Alert, Senders


async def send(alert: Alert, config: dict, senders: Senders) -> bool:
    to = config.get("to")
    if not to or senders.smtp is None:
        return False
    subject = f"[Vantari][{alert.severity.value.upper()}] {alert.title}"
    return await senders.smtp(to=to, subject=subject, body=alert.text(), config=config)
