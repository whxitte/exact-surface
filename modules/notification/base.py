"""Notification primitives: the Alert payload + pluggable senders (§module 34-38).

An ``Alert`` is already safe to transmit — secrets/leaks are formatted from their
stored MASKED fields, so a full secret value never reaches a channel (§9c). The
``Senders`` bundle injects the HTTP/SMTP transports so every channel is testable
offline (capture the calls) and the codebase imports without aiohttp present.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from core.severity import Severity

HttpPost = Callable[[str, dict], Awaitable[int]]  # (url, json_body) -> status code
SmtpSend = Callable[..., Awaitable[bool]]


@dataclass
class Alert:
    title: str
    severity: Severity
    program: str
    location: str
    module: str
    detail: str = ""  # already masked / safe
    reference: str = ""

    def text(self) -> str:
        """Plain-text rendering for text-only channels (telegram/email/webhook)."""
        lines = [
            f"[{self.severity.value.upper()}] {self.title}",
            f"Program:  {self.program}",
            f"Location: {self.location}",
            f"Module:   {self.module}",
        ]
        if self.detail:
            lines.append(f"Detail:   {self.detail}")
        if self.reference:
            lines.append(f"Ref:      {self.reference}")
        return "\n".join(lines)


@dataclass
class Senders:
    http: HttpPost
    smtp: SmtpSend | None = None


# Discord/Slack embed colors per severity.
_COLORS: dict[Severity, int] = {
    Severity.CRITICAL: 0xEF4444,
    Severity.HIGH: 0xF97316,
    Severity.MEDIUM: 0xF59E0B,
    Severity.LOW: 0x0EA5E9,
    Severity.INFO: 0x71717A,
}


def severity_color(sev: Severity) -> int:
    return _COLORS.get(sev, _COLORS[Severity.INFO])


async def default_http(url: str, payload: dict) -> int:  # pragma: no cover - real network
    import aiohttp

    async with aiohttp.ClientSession() as session:
        async with session.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=15)) as resp:
            return resp.status


def default_senders() -> Senders:
    return Senders(http=default_http)
