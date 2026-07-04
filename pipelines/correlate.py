"""Correlation pipeline (module 27) — read all signals, return prioritized issues.

Computed on demand (not persisted): reads the tenant's assets/findings/secrets/
leaks/CVE-matches/ports for a program and returns correlated, risk-ranked issues
for the dashboard and priority alerting.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from core.tenant import TenantContext
from db.assets import AssetRepo
from db.cves import CveMatchRepo
from db.findings import FindingRepo
from db.leaks import LeakRepo
from db.ports import PortRepo
from db.secrets import SecretRepo
from modules.intelligence.correlator import correlate


async def run_correlate(*, mongo: Any, tenant: TenantContext, program_id: str) -> dict:
    tid = tenant.tenant_id

    async def _all(repo_cls) -> list[dict]:
        return await repo_cls.from_mongo(mongo).list(tid, program_id, limit=100_000)

    issues = correlate(
        assets=await _all(AssetRepo),
        findings=await _all(FindingRepo),
        secrets=await _all(SecretRepo),
        leaks=await _all(LeakRepo),
        cve_matches=await _all(CveMatchRepo),
        ports=await _all(PortRepo),
    )
    return {
        "count": len(issues),
        "chains": sum(1 for i in issues if i.is_chain),
        "issues": [asdict(i) for i in issues],
    }
