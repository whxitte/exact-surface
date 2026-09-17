"""Correlation pipeline (module 27) — read all signals, return prioritized issues.

Computed on demand (not persisted): reads the tenant's assets/findings/secrets/
leaks/CVE-matches/ports for a program and returns correlated, risk-ranked issues
for the dashboard and priority alerting.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from core.liveness import (
    annotate_gone,
    const_phase,
    finding_phase,
    phase_reference_starts,
)
from core.tenant import TenantContext
from db.assets import AssetRepo
from db.audit import ScanRunRepo
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

    # Correlate only what a re-run still reproduces. Reading the raw collections would
    # count records that have since aged out — most visibly the pre-policy Wix session
    # JWTs (52 stored, 2 live), which piled a stale "13× secret:jwt" chain onto a host.
    # Drop `gone` docs with exactly the phase map the API reader uses, so correlation
    # matches the dashboard. Leaks have no phase reference (like the reader) so pass
    # through; assets stay whole because they define scope.
    runs = await ScanRunRepo.from_mongo(mongo).list(tid, program_id, limit=500)
    refs = phase_reference_starts(runs)

    def _live(docs: list[dict], phase_of) -> list[dict]:
        annotate_gone(docs, refs, phase_of)
        return [d for d in docs if not d.get("gone")]

    issues = correlate(
        assets=await _all(AssetRepo),
        findings=_live(await _all(FindingRepo), finding_phase),
        secrets=_live(await _all(SecretRepo), const_phase("secrets")),
        leaks=await _all(LeakRepo),
        cve_matches=_live(await _all(CveMatchRepo), const_phase("cve_watch")),
        ports=_live(await _all(PortRepo), const_phase("port_scan")),
    )
    return {
        "count": len(issues),
        "chains": sum(1 for i in issues if i.is_chain),
        "issues": [asdict(i) for i in issues],
    }
