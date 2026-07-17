"""Port-scan pipeline (modules 11–12).

Scope enforces the §9b boundary hard: only assets whose scope decision permits
PORT_SCAN (i.e. confirmed-dedicated IPs) are ever scanned — CDN/cloud-shared and
unconfirmed hosts are skipped entirely. naabu discovers open ports; nmap (optional)
adds service/version. New open ports feed the delta monitor's "new port" signal.
"""

from __future__ import annotations

from typing import Any

from core.config import get_settings
from core.hashing import port_fingerprint
from core.logging import logger
from core.models import Port
from core.ratelimit import subprocess_rate_for
from core.scope import Action, ProgramScope, ScopeEngine
from core.tenant import TenantContext
from daemon.metrics import REGISTRY
from db.assets import AssetRepo
from db.ports import PortRepo
from modules.ports.naabu import scan_ports


async def run_port_scan(
    *,
    mongo: Any,
    engine: ScopeEngine,
    scope: ProgramScope,
    tenant: TenantContext,
    program_id: str,
    timeout: float,
    targets: set[str] | None = None,
    naabu=scan_ports,
    nmap=None,
) -> dict:
    assets = await AssetRepo.from_mongo(mongo).list(tenant.tenant_id, program_id, limit=100_000)
    assets = [a for a in assets if a.get("monitored", True)]  # skip user-muted assets
    if targets:  # cascade: scope this run to the newly discovered hosts
        assets = [a for a in assets if a["hostname"] in targets]

    scannable = [
        a["hostname"]
        for a in assets
        if engine.evaluate(a["hostname"], a.get("resolved_ips", []), scope).permits(
            Action.PORT_SCAN
        )
    ]
    if not scannable:
        logger.info("port-scan {}: no confirmed-dedicated hosts to scan", program_id)
        return {
            "scannable": 0,
            "ports": 0,
            "new": 0,
            "skipped": True,
            "note": "no confirmed-dedicated hosts — CDN/cloud-shared IPs are HTTP-probe only (§9b)",
        }
    # §3.8b: the token-bucket limiter cannot govern naabu — it is a subprocess
    # sending its own packets — so the politeness ceiling must be handed to the
    # tool. Derive an aggregate rate that keeps the PER-TARGET rate within the cap,
    # and publish both so the ceiling is verifiable from metrics (§7 Phase D exit)
    # rather than merely asserted.
    cap = get_settings().global_rate_per_target
    rate = subprocess_rate_for(len(scannable), cap)
    per_target = rate / max(1, len(scannable))
    REGISTRY.set(
        "vantari_politeness_rate_limit_pps",
        cap,
        help="Configured max packets/sec per target IP (§3.8b)",
    )
    REGISTRY.set(
        "vantari_port_scan_rate_pps",
        rate,
        help="Aggregate packets/sec handed to naabu for the last port scan",
    )
    REGISTRY.set(
        "vantari_port_scan_per_target_pps",
        per_target,
        help="Derived per-target packets/sec for the last port scan; must stay <= the cap",
    )
    logger.info(
        "port-scanning {} dedicated host(s) with naabu (rate {}/s aggregate, {:.1f}/s per target,"
        " cap {}/s)",
        len(scannable),
        rate,
        per_target,
        cap,
    )
    open_ports = await naabu(scannable, timeout, rate=rate)

    # Optional service/version enrichment per IP.
    service_by = {}
    if nmap is not None and open_ports:
        ports_by_ip: dict[str, list[int]] = {}
        for p in open_ports:
            ports_by_ip.setdefault(p["ip"], []).append(p["port"])
        for ip, ports in ports_by_ip.items():
            for svc in await nmap(ip, ports, timeout):
                service_by[(ip, svc["port"])] = svc

    models = []
    for p in open_ports:
        svc = service_by.get((p["ip"], p["port"]), {})
        models.append(
            Port(
                tenant_id=tenant.tenant_id,
                program_id=program_id,
                fingerprint=port_fingerprint(program_id, p["ip"], p["port"], p["protocol"]),
                ip=p["ip"],
                port=p["port"],
                protocol=p["protocol"],
                service=svc.get("service"),
                version=svc.get("version"),
            )
        )
    total, new = await PortRepo.from_mongo(mongo).upsert_many(models)

    logger.info(
        "port-scan {}: {} scannable hosts, {} ports, {} new", program_id, len(scannable), total, new
    )
    return {"scannable": len(scannable), "ports": total, "new": new}
