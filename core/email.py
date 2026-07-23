"""Transactional email — provider-agnostic transport (§ Phase C email verification).

Two transports, chosen by ``settings.email_transport``:

* ``log``  — writes the message (and any link) to the log. The dev default: no
  account, no network, works out of the box. Also what tests assert against.
* ``smtp`` — sends via stdlib ``smtplib`` over ``asyncio.to_thread`` (no async
  dependency). Works with ANY provider's SMTP credentials — Resend, Brevo,
  Amazon SES, Postmark, Mailgun — so the provider choice is just ``.env`` config.

The *flow* (token issue/expiry/verify/resend) lives in the auth routes; this module
only knows how to put a message on the wire. ``send`` never raises: a transport
failure is logged and returns ``False`` so a signup is never blocked by email.
"""

from __future__ import annotations

import asyncio
import smtplib
from dataclasses import dataclass
from email.message import EmailMessage as _MimeMessage
from typing import Protocol

from core.config import Settings, get_settings
from core.logging import logger


@dataclass(frozen=True)
class EmailMessage:
    to: str
    subject: str
    text: str
    html: str | None = None


class EmailSender(Protocol):
    async def send(self, msg: EmailMessage) -> bool: ...


class LogEmailSender:
    """Dev/test transport: record the email instead of sending it."""

    def __init__(self) -> None:
        self.sent: list[EmailMessage] = []

    async def send(self, msg: EmailMessage) -> bool:
        self.sent.append(msg)
        logger.info("[email:log] to={} subject={!r}\n{}", msg.to, msg.subject, msg.text)
        return True


class SmtpEmailSender:
    """Production transport over any provider's SMTP endpoint (stdlib, threaded)."""

    def __init__(self, settings: Settings) -> None:
        self._s = settings

    def _send_blocking(self, msg: EmailMessage) -> bool:
        s = self._s
        mime = _MimeMessage()
        mime["From"] = s.email_from
        mime["To"] = msg.to
        mime["Subject"] = msg.subject
        mime.set_content(msg.text)
        if msg.html:
            mime.add_alternative(msg.html, subtype="html")
        with smtplib.SMTP(s.smtp_host or "", s.smtp_port, timeout=15) as server:
            if s.smtp_starttls:
                server.starttls()
            if s.smtp_user and s.smtp_password:
                server.login(s.smtp_user, s.smtp_password.get_secret_value())
            server.send_message(mime)
        return True

    async def send(self, msg: EmailMessage) -> bool:
        try:
            return await asyncio.to_thread(self._send_blocking, msg)
        except Exception as exc:  # noqa: BLE001 - email must never break the caller
            logger.warning("smtp send to {} failed: {}", msg.to, type(exc).__name__)
            return False


def get_email_sender(settings: Settings | None = None) -> EmailSender:
    settings = settings or get_settings()
    if settings.email_transport == "smtp" and settings.smtp_host:
        return SmtpEmailSender(settings)
    if settings.email_transport == "smtp":  # misconfigured — degrade loudly, don't crash
        logger.warning("email_transport=smtp but smtp_host unset — falling back to log transport")
    return LogEmailSender()


def build_verification_email(*, to: str, link: str) -> EmailMessage:
    text = (
        "Welcome to ExactSurface.\n\n"
        "Confirm your email address to activate your account:\n"
        f"{link}\n\n"
        "This link expires in 24 hours. If you didn't sign up, ignore this email."
    )
    html = (
        f"<p>Welcome to ExactSurface.</p><p>Confirm your email to activate your account:</p>"
        f'<p><a href="{link}">Verify my email</a></p>'
        "<p>This link expires in 24 hours. If you didn't sign up, ignore this email.</p>"
    )
    return EmailMessage(to=to, subject="Verify your ExactSurface email", text=text, html=html)
