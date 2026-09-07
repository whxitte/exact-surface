"""Cloud-bucket exposure pipeline (module 18).

Permutes likely bucket names from the program's apex label and checks each across
S3/GCS/Azure. This is **passive recon against a public cloud-storage API** — the
same class as crt.sh or wayback, and deliberately *not* scope-gated against the
operator's apex, because `acme-backup.s3.amazonaws.com` is by definition not a
subdomain of `acme.com`. We contact Amazon/Google/Microsoft's public endpoints,
never the operator's infrastructure, and only ever with a plain GET.

**Attribution is a guess, and we say so.** A bucket named after the operator's
domain label may belong to someone else entirely — the name is the only evidence.
So:

* only a **publicly listable** bucket (HTTP 200) becomes a Finding, because that
  is the one outcome that is actionable regardless of who owns it;
* a bucket that merely *exists* but denies access (403) is counted for the run
  summary and **not** persisted — "some bucket somewhere has a similar name" is
  unattributable noise, and shipping it as a finding is exactly the info-flood
  that buries real triage (§15 signal quality).

Every finding's description states that ownership is name-derived and unverified,
so nobody reads it as proof.
"""

from __future__ import annotations

import asyncio
from typing import Any

from core.hashing import finding_fingerprint
from core.logging import logger
from core.models import Finding
from core.severity import Severity
from core.tenant import TenantContext
from db.findings import FindingRepo
from modules.osint.cloud_buckets import enumerate_buckets
from modules.osint.cloud_buckets import permutations as bucket_permutations

#: Bucket probes are cheap GETs against three public providers, but there are
#: ~45 of them per program — keep the fan-out polite.
CHECK_CONCURRENCY = 8

_UNVERIFIED = (
    "Ownership is inferred from the bucket name matching your domain label and is "
    "NOT verified — the bucket may belong to another organisation. Confirm before "
    "acting."
)


async def default_checker(url: str) -> int | None:  # pragma: no cover - real network
    """Return the HTTP status for a bucket URL, or None if unreachable."""
    import aiohttp

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                return resp.status
    except Exception:  # noqa: BLE001 - unreachable/DNS failure is simply "no bucket"
        return None


def _bounded(checker, sem: asyncio.Semaphore):
    async def check(url: str) -> int | None:
        async with sem:
            return await checker(url)

    return check


async def run_cloud_buckets(
    *,
    mongo: Any,
    tenant: TenantContext,
    program_id: str,
    apex: str,
    checker=None,
) -> dict:
    checker = checker or default_checker
    sem = asyncio.Semaphore(CHECK_CONCURRENCY)

    # Show the work: which names we derived and which providers we are asking. A bare
    # "0 candidates checked" tells the user nothing about what was actually attempted.
    candidates = bucket_permutations(apex)
    providers = sorted({p for p, _n, _u in candidates})
    logger.info(
        "cloud-buckets {}: derived {} candidate name(s) across {} → probing {} URL(s)",
        apex,
        len({n for _p, n, _u in candidates}),
        ", ".join(providers),
        len(candidates),
    )
    found = await enumerate_buckets(apex, checker=_bounded(checker, sem))
    for bucket in found:
        logger.info(
            "cloud-buckets: {} {} → HTTP {} ({})",
            bucket.get("provider"),
            bucket.get("name"),
            bucket.get("status"),
            "PUBLIC" if bucket.get("public") else "exists but private",
        )

    public = [b for b in found if b.get("public")]
    private = [b for b in found if not b.get("public")]

    models = [
        Finding(
            tenant_id=tenant.tenant_id,
            program_id=program_id,
            fingerprint=finding_fingerprint(program_id, "exposed-cloud-bucket", b["url"]),
            check_id="exposed-cloud-bucket",
            module="cloud_buckets",
            location=b["url"],
            name=f"Publicly listable {b['provider'].upper()} bucket: {b['name']}",
            description=(
                f"The {b['provider'].upper()} bucket '{b['name']}' is publicly listable "
                f"(HTTP {b['status']}), exposing its object index to anyone. " + _UNVERIFIED
            ),
            severity=Severity.HIGH,
            reproduction=f"curl -s '{b['url']}'",
            raw={"provider": b["provider"], "bucket": b["name"], "status": b["status"]},
        )
        for b in public
    ]
    res = await FindingRepo.from_mongo(mongo).upsert_all(models)
    new = sum(1 for x in res if x.inserted)

    # `found` is candidates CONFIRMED TO EXIST (public or private) -- every one of the
    # `len(candidates)` derived names was already probed above ("probing N URL(s)"),
    # so this line must not say "checked" again: read cold, "0 candidate(s) checked"
    # after "probing 45 URL(s)" sounds like the probing never happened, when the real
    # (and completely normal) outcome is that none of the 45 guessed names resolved to
    # an actual bucket anywhere.
    logger.info(
        "cloud-buckets {}: {}/{} candidate name(s) exist — {} public ({} new finding(s)),"
        " {} exist-but-private (not persisted — unattributable)",
        apex,
        len(found),
        len(candidates),
        len(public),
        new,
        len(private),
    )
    return {
        "checked": len(found),
        "public": len(public),
        "private": len(private),
        "new": new,
    }
