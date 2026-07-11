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

import asyncio
from typing import Any

from core.logging import logger
from core.severity import Severity
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

#: deliver in parallel (a hanging channel like telegram must not serialize the whole
#: stage into a timeout) and cap per source so a noisy scan can't spam a channel.
DELIVER_CONCURRENCY = 10
DELIVER_TIMEOUT = 20.0
MAX_ALERTS_PER_SOURCE = 100

_SEV_RANK = {s: i for i, s in enumerate(Severity)}  # critical=0 … info last


def _by_severity(doc: dict) -> int:
    try:
        return _SEV_RANK.get(Severity(doc.get("severity", "info")), 99)
    except ValueError:
        return 99


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

    sem = asyncio.Semaphore(DELIVER_CONCURRENCY)

    async def _deliver(alert, channel) -> bool:
        async with sem:
            try:
                return await asyncio.wait_for(deliver(alert, channel, senders), DELIVER_TIMEOUT)
            except (Exception, TimeoutError) as exc:  # noqa: BLE001
                logger.warning(
                    "notify: {} delivery gave up: {}", channel.get("type"), type(exc).__name__
                )
                return False

    delivered = 0
    for repo_cls, formatter, alertable in _SOURCES:
        repo = repo_cls.from_mongo(mongo)
        items = await repo.list(tenant.tenant_id, program_id, is_new=True, limit=1000)
        # highest-severity first, capped — deliver the important ones now, the rest
        # next run (they keep is_new until delivered), so channels aren't spammed.
        items = sorted(items, key=_by_severity)[:MAX_ALERTS_PER_SOURCE]

        # Build every (doc, channel) delivery up front and run them CONCURRENTLY.
        plan: list[tuple[str, Any]] = []
        for doc in items:
            if alertable and not alertable(doc):
                continue
            alert = formatter(doc, apex)
            for channel in channels:
                if passes(alert, channel):
                    plan.append((doc["fingerprint"], _deliver(alert, channel)))
        if not plan:
            continue
        outcomes = await asyncio.gather(*(coro for _, coro in plan))

        delivered_fps: set[str] = set()
        for (fp, _), ok in zip(plan, outcomes, strict=True):
            if ok:
                delivered += 1
                delivered_fps.add(fp)
        if delivered_fps:
            await repo.clear_is_new(tenant.tenant_id, list(delivered_fps))

    logger.info("notify {}: {} channels, {} deliveries", program_id, len(channels), delivered)
    return {"channels": len(channels), "delivered": delivered}
