"""Service-identification pipeline (module 12, optional) — nmap -sV on open ports.

Enriches the open ports naabu already discovered with service/version banners.
Optional: runs only when the ``service_scan`` module is enabled, and only has work
to do when a prior port scan found open ports (which itself needs dedicated or
scan-shared-infra-authorized hosts).
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
from typing import Any

from core.hashing import port_fingerprint
from core.logging import logger
from core.models import Port
from core.scope import ProgramScope, ScopeEngine
from core.tenant import TenantContext
from db.ports import PortRepo
from modules.ports.nmap import service_scan as nmap_service_scan

#: nmap -sV is slow; bound each host and run a few concurrently so a big IP set
#: (dozens of hosts) stays well inside the stage budget instead of blowing it.
PER_IP_TIMEOUT = 60.0
CONCURRENCY = 8


async def run_service_scan(
    *,
    mongo: Any,
    engine: ScopeEngine,
    scope: ProgramScope,
    tenant: TenantContext,
    program_id: str,
    timeout: float,
    nmap=nmap_service_scan,
) -> dict:
    ports = await PortRepo.from_mongo(mongo).list(tenant.tenant_id, program_id, limit=100_000)
    if not ports:
        return {
            "ports": 0,
            "enriched": 0,
            "new": 0,
            "skipped": True,
            "note": "no open ports — run the port scan first",
        }

    ports_by_ip: dict[str, list[int]] = defaultdict(list)
    for p in ports:
        ports_by_ip[p["ip"]].append(p["port"])

    per_ip = min(timeout, PER_IP_TIMEOUT)
    logger.info(
        "service_scan: nmap -sV on {} IP(s) (≤{:.0f}s each, {} at a time)",
        len(ports_by_ip), per_ip, CONCURRENCY,
    )
    sem = asyncio.Semaphore(CONCURRENCY)

    async def _scan_ip(ip: str, plist: list[int]) -> tuple[str, dict]:
        # Each host is bounded and isolated: a slow/failing nmap yields no data for
        # that host but never sinks the stage (which would fail the whole run).
        async with sem:
            try:
                return ip, {s["port"]: s for s in await nmap(ip, plist, per_ip)}
            except Exception as exc:  # noqa: BLE001
                logger.warning("service_scan: nmap failed for {}: {}", ip, exc)
                return ip, {}

    svc_maps = dict(
        await asyncio.gather(*(_scan_ip(ip, pl) for ip, pl in ports_by_ip.items()))
    )

    updated: list[Port] = []
    for p in ports:
        svc = svc_maps.get(p["ip"], {}).get(p["port"])
        if not svc:
            continue
        updated.append(
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
    # re-upsert updates service/version in place (fingerprint unchanged → no new rows)
    await PortRepo.from_mongo(mongo).upsert_many(updated)
    logger.info("service_scan: enriched {}/{} port(s)", len(updated), len(ports))
    return {"ports": len(ports), "enriched": len(updated), "new": 0}
