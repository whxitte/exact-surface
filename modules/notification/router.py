"""Per-tenant notification routing (module 39).

Maps a channel type to its sender, applies the channel's severity threshold, and
turns stored DB documents into safe :class:`Alert` payloads. Secret/leak alerts
are built from the MASKED fields only — plaintext never leaves the database (§9c).
"""

from __future__ import annotations

from core.logging import logger
from core.models import ChannelType
from core.severity import Severity
from modules.notification import discord, email, slack, telegram, webhook
from modules.notification.base import Alert, Senders

_DISPATCH = {
    ChannelType.DISCORD: discord.send,
    ChannelType.SLACK: slack.send,
    ChannelType.TELEGRAM: telegram.send,
    ChannelType.WEBHOOK: webhook.send,
    ChannelType.EMAIL: email.send,
}


def _sev(value) -> Severity:
    try:
        return Severity(value)
    except ValueError:
        return Severity.INFO


def passes(alert: Alert, channel: dict) -> bool:
    """True if the alert meets the channel's minimum severity threshold."""
    return alert.severity.rank >= _sev(channel.get("min_severity", "medium")).rank


async def deliver(alert: Alert, channel: dict, senders: Senders) -> bool:
    fn = _DISPATCH.get(ChannelType(channel["type"]))
    if fn is None:
        return False
    try:
        return await fn(alert, channel.get("config") or {}, senders)
    except Exception as exc:  # noqa: BLE001 - a channel failure must not stop others
        # str(exc) is empty for timeout/connection errors — show the type so the
        # log is actionable ("TimeoutError" / "ClientConnectorError" vs blank).
        logger.warning(
            "notification delivery failed ({}): {}: {}",
            channel.get("type"),
            type(exc).__name__,
            exc,
        )
        return False


# -- doc → Alert (all safe/masked) -------------------------------------------
def alert_from_finding(doc: dict, program: str) -> Alert:
    refs = doc.get("references") or []
    return Alert(
        title=doc.get("name") or doc.get("check_id", "finding"),
        severity=_sev(doc.get("severity")),
        program=program,
        location=doc.get("location", ""),
        module=doc.get("module", "nuclei"),
        reference=refs[0] if refs else "",
    )


def alert_from_secret(doc: dict, program: str) -> Alert:
    return Alert(
        title=f"Exposed secret: {doc.get('kind')}",
        severity=_sev(doc.get("severity", "high")),
        program=program,
        location=doc.get("source_locator", ""),
        module="secretfinder",
        detail=f"{doc.get('masked')} — rotate immediately",
    )


def alert_from_leak(doc: dict, program: str) -> Alert:
    return Alert(
        title=f"Leaked secret ({doc.get('source', 'github')}): {doc.get('kind')}",
        severity=_sev(doc.get("severity", "high")),
        program=program,
        location=doc.get("url") or doc.get("repo", ""),
        module="github_osint",
        detail=f"{doc.get('masked')} — rotate immediately",
    )


def alert_from_cve(doc: dict, program: str) -> Alert:
    kev = " [KEV]" if doc.get("on_kev") else ""
    return Alert(
        title=f"{doc.get('cve_id')}{kev}",
        severity=_sev(doc.get("severity")),
        program=program,
        location=doc.get("cpe", ""),
        module="cve_watch",
        detail=f"confidence={doc.get('confidence')}",
    )


def cve_is_alertable(doc: dict) -> bool:
    return doc.get("confidence") == "high" or bool(doc.get("on_kev"))


#: ports where merely being open is noteworthy (remote admin, databases, caches) — an
#: alert for one of these rates HIGH; any other newly-open port is MEDIUM.
_SENSITIVE_PORTS = {
    21,
    22,
    23,
    25,
    135,
    139,
    445,
    1433,
    1521,
    3306,
    3389,
    5432,
    5900,
    6379,
    9200,
    11211,
    27017,
}


def alert_from_asset(doc: dict, program: str) -> Alert:
    """A newly-discovered subdomain (change event, not a vulnerability)."""
    return Alert(
        title=f"New subdomain: {doc.get('hostname', '')}",
        severity=Severity.INFO,
        program=program,
        location=doc.get("hostname", ""),
        module="ingest",
        detail="appeared after the baseline scan",
    )


def alert_from_port(doc: dict, program: str) -> Alert:
    """A newly-observed open port (change event)."""
    port = int(doc.get("port", 0) or 0)
    svc = doc.get("service") or ""
    product = doc.get("product") or ""
    banner = f"{svc}{f' ({product})' if product else ''}".strip()
    return Alert(
        title=f"New open port {port}/{doc.get('protocol', 'tcp')}",
        severity=Severity.HIGH if port in _SENSITIVE_PORTS else Severity.MEDIUM,
        program=program,
        location=f"{doc.get('ip', '')}:{port}",
        module="naabu",
        detail=banner or "no banner",
    )
