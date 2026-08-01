"""Cloud asset enumeration stage — what the customer's cloud accounts say they own.

The strongest ownership signal in the product: the provider itself confirms these are
the customer's resources. Runs only when a cloudlist provider config is configured, and
is opt-in because it needs credentials the customer must deliberately supply.

Discovered names still pass through the scope engine before anything is scanned. A
provider saying "this is yours" answers ownership, not authorisation — a shared-tenancy
address inside their account can still front infrastructure they do not exclusively
control, and §9b does not bend for a convenient answer.
"""

from __future__ import annotations

from typing import Any

from core.hashing import asset_fingerprint, finding_fingerprint
from core.logging import logger
from core.models import Asset, Finding
from core.scope import ProgramScope
from core.severity import Severity
from core.tenant import TenantContext
from db.assets import AssetRepo
from db.findings import FindingRepo
from modules.recon import cloudlist


async def run_cloud_assets(
    *,
    mongo: Any,
    scope: ProgramScope,
    tenant: TenantContext,
    program_id: str,
    timeout: float = 300.0,
    config_path: str | None = None,
    enumerate_fn=None,
) -> dict:
    """Enumerate the customer's cloud assets and record the in-scope ones."""
    enumerate_fn = enumerate_fn or cloudlist.enumerate_assets

    if config_path is None:
        from core.config import get_settings

        config_path = getattr(get_settings(), "cloudlist_config", None) or ""

    if not config_path:
        logger.info("cloud_assets: no cloudlist provider config set — nothing to enumerate")
        return {
            "skipped": True,
            "note": (
                "no cloud credentials configured. Point EXACTSURFACE_CLOUDLIST_CONFIG at a "
                "cloudlist provider file with READ-ONLY keys to enumerate your cloud assets."
            ),
        }

    assets = await enumerate_fn(config_path, timeout)
    if not assets:
        return {"discovered": 0, "in_scope": 0, "assets": 0, "new": 0}

    own = tuple(scope.verified_apexes)
    in_scope: list[cloudlist.CloudAsset] = []
    outside: list[cloudlist.CloudAsset] = []
    for asset in assets:
        if asset.is_ip:
            # An IP with no name is real surface but cannot be scope-checked by domain.
            # Recorded as intelligence below, never auto-scanned.
            outside.append(asset)
            continue
        if any(asset.hostname == a or asset.hostname.endswith("." + a) for a in own if a):
            in_scope.append(asset)
        else:
            outside.append(asset)

    records = [
        Asset(
            tenant_id=tenant.tenant_id,
            program_id=program_id,
            fingerprint=asset_fingerprint(program_id, a.hostname),
            hostname=a.hostname,
            source=f"cloudlist:{a.provider}",
        )
        for a in in_scope
    ]
    total, new = await AssetRepo.from_mongo(mongo).upsert_many(records)

    findings: list[Finding] = []
    if outside:
        # Assets the cloud account owns that are NOT covered by a verified domain. This
        # is the most valuable output of the module — it is precisely the shadow IT a
        # security team does not know about — but it is reported, never scanned, because
        # nobody has proven authorisation for it.
        sample = sorted({a.value for a in outside})[:100]
        by_provider = sorted({a.provider for a in outside})
        findings.append(
            Finding(
                tenant_id=tenant.tenant_id,
                program_id=program_id,
                fingerprint=finding_fingerprint(program_id, "cloud-unmonitored", program_id),
                check_id="cloud-assets-outside-monitored-scope",
                module="cloud_assets",
                location=program_id,
                locator=",".join(by_provider),
                name=f"{len(outside)} cloud asset(s) are not covered by a verified domain",
                description=(
                    f"Your cloud account(s) ({', '.join(by_provider)}) report "
                    f"{len(outside)} internet-facing asset(s) that do not fall under any "
                    "domain you have verified here, so ExactSurface is not monitoring "
                    "them. These are the ones worth looking at hardest — an asset nobody "
                    "attached a monitored name to is usually an asset nobody is watching."
                    "\n\nAdd the relevant domain and verify it to bring them in scope. "
                    "Nothing here has been scanned: the cloud provider confirms you own "
                    "them, which is not the same as authorisation to test them.\n\n"
                    + "\n".join(f"  {v}" for v in sample[:40])
                ),
                severity=Severity.MEDIUM,
                reproduction=f"cloudlist -config {config_path} -json",
                raw={"assets": sample, "providers": by_provider, "count": len(outside)},
            )
        )
    f_total, f_new = await FindingRepo.from_mongo(mongo).upsert_many(findings)

    logger.info(
        "cloud_assets: {} asset(s) from cloud accounts → {} in scope ({} new), "
        "{} outside any verified domain",
        len(assets),
        len(in_scope),
        new,
        len(outside),
    )
    return {
        "discovered": len(assets),
        "in_scope": len(in_scope),
        "outside_scope": len(outside),
        "assets": total,
        "new": new,
        "findings": f_new,
        "cascade_targets": [a.hostname for a in in_scope],
    }
