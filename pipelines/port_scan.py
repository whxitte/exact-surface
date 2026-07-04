"""Port-scan pipeline (modules 11–12).

Scope enforces the §9b boundary hard: only assets whose scope decision permits
PORT_SCAN (i.e. confirmed-dedicated IPs) are ever scanned — CDN/cloud-shared and
unconfirmed hosts are skipped entirely. naabu discovers open ports; nmap (optional)
adds service/version. New open ports feed the delta monitor's "new port" signal.
"""

from __future__ import annotations

from typing import Any

from core.hashing import port_fingerprint
from core.logging import logger
from core.models import Port
from core.scope import Action, ProgramScope, ScopeEngine
from core.tenant import TenantContext
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
    naabu=scan_ports,
    nmap=None,
) -> dict:
    assets = await AssetRepo.from_mongo(mongo).list(tenant.tenant_id, program_id, limit=100_000)

    scannable = [
        a["hostname"]
        for a in assets
        if engine.evaluate(a["hostname"], a.get("resolved_ips", []), scope).permits(
            Action.PORT_SCAN
        )
    ]
    open_ports = await naabu(scannable, timeout)

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
