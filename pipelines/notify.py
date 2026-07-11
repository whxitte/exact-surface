"""Notification pipeline (module 39) — new signals → per-tenant channels.

Gathers the program's genuinely-new (``is_new``) signals and delivers each to every
enabled channel, subject to the program's **alert policy** (core.alert_policy):

  * vulnerability signals (findings / secrets / leaks / CVEs) — each family can be
    switched off, and all are gated by a severity floor (CVEs additionally by a CVSS
    floor). The per-channel severity threshold still applies on top.
  * change events (a new subdomain / a new open port) — opt-in toggles that fire only
    AFTER the baseline scan (``initial_scan_completed_at``), so the first enumeration
    doesn't page for every subdomain. New-port events are further filtered by an
    nmap-style port spec. Change events bypass the per-channel severity threshold —
    enabling the toggle is the explicit opt-in.

``is_new`` is cleared only for delivered items, so an alert fires exactly once per real
appearance. Secrets/leaks are formatted from masked fields only (§9c).
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any

from core.alert_policy import effective_alert_policy, meets_severity_floor, port_matches
from core.logging import logger
from core.severity import Severity
from core.tenant import TenantContext
from db.assets import AssetRepo
from db.cves import CveMatchRepo
from db.findings import FindingRepo
from db.leaks import LeakRepo
from db.notifications import NotificationChannelRepo
from db.ports import PortRepo
from db.programs import ProgramRepo
from db.secrets import SecretRepo
from db.tenants import TenantRepo
from modules.notification.base import Senders, default_senders
from modules.notification.router import (
    alert_from_asset,
    alert_from_cve,
    alert_from_finding,
    alert_from_leak,
    alert_from_port,
    alert_from_secret,
    cve_is_alertable,
    deliver,
    passes,
)

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


def _first_seen_after(baseline: Any) -> Callable[[dict], bool]:
    """Keep only items that first appeared strictly after the baseline scan."""

    def keep(doc: dict) -> bool:
        fs = doc.get("first_seen")
        try:
            return fs is not None and fs > baseline
        except TypeError:  # tz-naive vs aware, or non-datetime — treat as "not after"
            return False

    return keep


def _cve_keep(policy: dict) -> Callable[[dict], bool]:
    floor = float(policy.get("cve_min_cvss", 0.0) or 0.0)

    def keep(doc: dict) -> bool:
        if not cve_is_alertable(doc):
            return False
        if floor > 0:
            cvss = doc.get("cvss")
            if cvss is None or float(cvss) < floor:
                return False
        return meets_severity_floor(doc.get("severity", "info"), policy)

    return keep


def _sev_keep(policy: dict, default: str) -> Callable[[dict], bool]:
    return lambda doc: meets_severity_floor(doc.get("severity", default), policy)


def _build_sources(policy: dict, baseline: Any) -> list[tuple]:
    """(repo_cls, formatter, keep_predicate, is_event) for each enabled alert family."""
    sources: list[tuple] = []
    if policy["alert_findings"]:
        sources.append((FindingRepo, alert_from_finding, _sev_keep(policy, "info"), False))
    if policy["alert_secrets"]:
        sources.append((SecretRepo, alert_from_secret, _sev_keep(policy, "high"), False))
    if policy["alert_leaks"]:
        sources.append((LeakRepo, alert_from_leak, _sev_keep(policy, "high"), False))
    if policy["alert_cves"]:
        sources.append((CveMatchRepo, alert_from_cve, _cve_keep(policy), False))
    # change events only fire once a baseline exists (initial enumeration established).
    if policy["alert_new_assets"] and baseline:
        sources.append((AssetRepo, alert_from_asset, _first_seen_after(baseline), True))
    if policy["alert_new_ports"] and baseline:
        after = _first_seen_after(baseline)
        spec = policy.get("port_filter", "")
        sources.append(
            (
                PortRepo,
                alert_from_port,
                lambda d, _after=after, _spec=spec: (
                    _after(d) and port_matches(_spec, int(d.get("port", 0) or 0))
                ),
                True,
            )
        )
    return sources


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
    tenant_doc = await TenantRepo.from_mongo(mongo).get(tenant.tenant_id)
    policy = effective_alert_policy(
        (program or {}).get("alert_policy"), (tenant_doc or {}).get("alert_policy")
    )
    apex = program["apex_domain"] if program else program_id
    baseline = (program or {}).get("initial_scan_completed_at")

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
    for repo_cls, formatter, keep, is_event in _build_sources(policy, baseline):
        repo = repo_cls.from_mongo(mongo)
        items = await repo.list(tenant.tenant_id, program_id, is_new=True, limit=1000)
        # highest-severity first, capped — deliver the important ones now, the rest
        # next run (they keep is_new until delivered), so channels aren't spammed.
        items = sorted(items, key=_by_severity)[:MAX_ALERTS_PER_SOURCE]

        plan: list[tuple[str, Any]] = []
        for doc in items:
            if not keep(doc):
                continue
            alert = formatter(doc, apex)
            for channel in channels:
                # change events bypass the channel severity floor (explicit opt-in);
                # vulnerability alerts must clear it.
                if is_event or passes(alert, channel):
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
