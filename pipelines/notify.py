"""Notification pipeline (module 39) — new findings → per-tenant channels.

Gathers the program's genuinely-new (``is_new``) findings, secrets, leaks, and
alertable CVE matches, delivers each to every enabled channel that meets its
severity threshold, then clears ``is_new`` **only for delivered items** — so an
alert fires exactly once per real appearance, and nothing is silently dropped when
no channel is configured yet.

Secrets and leaks are formatted from their masked fields; the full value never
reaches a channel (§9c).
"""

from __future__ import annotations

from typing import Any

from core.logging import logger
from core.tenant import TenantContext
from db.cves import CveMatchRepo
from db.findings import FindingRepo
from db.leaks import LeakRepo
from db.notifications import NotificationChannelRepo
from db.programs import ProgramRepo
from db.secrets import SecretRepo
from modules.notification.base import Senders, default_senders
from modules.notification.router import (
    alert_from_cve,
    alert_from_finding,
    alert_from_leak,
    alert_from_secret,
    cve_is_alertable,
    deliver,
    passes,
)

# (repo, formatter, per-item alertable predicate)
_SOURCES = [
    (FindingRepo, alert_from_finding, None),
    (SecretRepo, alert_from_secret, None),
    (LeakRepo, alert_from_leak, None),
    (CveMatchRepo, alert_from_cve, cve_is_alertable),
]


async def run_notify(
    *,
    mongo: Any,
    tenant: TenantContext,
    program_id: str,
    senders: Senders | None = None,
) -> dict:
    senders = senders or default_senders()
    channels = [
        c
        for c in await NotificationChannelRepo.from_mongo(mongo).list(tenant.tenant_id)
        if c.get("enabled", True)
    ]
    if not channels:
        return {
            "channels": 0,
            "delivered": 0,
            "skipped": True,
            "note": "no notification channels configured",
        }

    program = await ProgramRepo.from_mongo(mongo).get(tenant.tenant_id, program_id)
    apex = program["apex_domain"] if program else program_id

    delivered = 0
    for repo_cls, formatter, alertable in _SOURCES:
        repo = repo_cls.from_mongo(mongo)
        items = await repo.list(tenant.tenant_id, program_id, is_new=True, limit=1000)
        delivered_fps: list[str] = []
        for doc in items:
            if alertable and not alertable(doc):
                continue
            alert = formatter(doc, apex)
            sent_any = False
            for channel in channels:
                if passes(alert, channel) and await deliver(alert, channel, senders):
                    delivered += 1
                    sent_any = True
            if sent_any:
                delivered_fps.append(doc["fingerprint"])
        if delivered_fps:
            await repo.clear_is_new(tenant.tenant_id, delivered_fps)

    logger.info("notify {}: {} channels, {} deliveries", program_id, len(channels), delivered)
    return {"channels": len(channels), "delivered": delivered}
