"""Transactional-email transport (core/email.py)."""

from __future__ import annotations

import asyncio

from core.config import Settings
from core.email import (
    LogEmailSender,
    SmtpEmailSender,
    build_verification_email,
    get_email_sender,
)


def _run(coro):
    return asyncio.run(coro)


def test_log_sender_records_message():
    sender = LogEmailSender()
    msg = build_verification_email(to="a@b.com", link="https://app/verify-email?token=xyz")
    assert _run(sender.send(msg)) is True
    assert len(sender.sent) == 1 and sender.sent[0].to == "a@b.com"
    assert "verify-email?token=xyz" in sender.sent[0].text


def test_verification_email_has_link_and_expiry_note():
    msg = build_verification_email(to="a@b.com", link="https://app/verify-email?token=T")
    assert "https://app/verify-email?token=T" in msg.text
    assert "expires" in msg.text.lower()
    assert msg.html and "Verify my email" in msg.html


def test_factory_picks_log_by_default():
    assert isinstance(get_email_sender(Settings(email_transport="log")), LogEmailSender)


def test_factory_picks_smtp_when_configured():
    s = Settings(email_transport="smtp", smtp_host="smtp.example.com")
    assert isinstance(get_email_sender(s), SmtpEmailSender)


def test_factory_falls_back_to_log_when_smtp_host_missing():
    # transport=smtp but no host → degrade to log rather than crash later.
    s = Settings(email_transport="smtp", smtp_host=None)
    assert isinstance(get_email_sender(s), LogEmailSender)


def test_smtp_send_never_raises_on_failure():
    # No SMTP server on this host/port → send returns False, does not raise.
    s = Settings(email_transport="smtp", smtp_host="127.0.0.1", smtp_port=1)
    sender = SmtpEmailSender(s)
    msg = build_verification_email(to="a@b.com", link="https://app/verify-email?token=T")
    assert _run(sender.send(msg)) is False
