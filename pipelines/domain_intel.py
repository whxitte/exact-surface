"""Domain intelligence — registration facts and email-spoofing exposure.

The two things an attacker learns about a domain before touching a single host: can I
spoof mail from it, and is the registration itself weak (expiring, unlocked)? Both are
answered from DNS and a public registry, so this stage is fully passive — no traffic to
the operator's infrastructure at all.

Cheap, fast, and high-signal: it usually produces the first real findings of a scan,
often before subdomain enumeration has finished.
"""

from __future__ import annotations

from typing import Any

from core.hashing import finding_fingerprint
from core.logging import logger
from core.models import Finding
from core.tenant import TenantContext
from db.domain_intel import DomainIntelRepo
from db.findings import FindingRepo
from modules.osint import email_security, rdap

#: DKIM selectors we probe. Kept short — each is a DNS query, and a miss proves nothing.
_DKIM_SELECTORS = email_security.COMMON_DKIM_SELECTORS[:6]


async def run_domain_intel(
    *,
    mongo: Any,
    tenant: TenantContext,
    program_id: str,
    apex: str,
    resolve_txt=None,
    rdap_fetch=None,
) -> dict:
    """Assess ``apex``'s email posture + registration. Returns counts for the stepper.

    ``resolve_txt(hostname) -> list[str]`` and ``rdap_fetch(url) -> dict`` are injected
    so the stage is offline-testable.
    """
    resolve_txt = resolve_txt or _default_resolve_txt
    findings: list[Finding] = []
    summary: dict = {}

    # -- email posture (SPF at the apex, DMARC at _dmarc, DKIM at <selector>._domainkey)
    try:
        spf_txt = await resolve_txt(apex)
        dmarc_txt = await resolve_txt(f"_dmarc.{apex}")
        dkim: dict[str, list[str]] = {}
        for selector in _DKIM_SELECTORS:
            try:
                dkim[selector] = await resolve_txt(f"{selector}._domainkey.{apex}")
            except Exception:  # noqa: BLE001 - a selector miss is not an error
                dkim[selector] = []
        # Absence findings ("No SPF", "No DMARC") are only safe when the lookups actually
        # worked. A flaky dnsx run that returns nothing for everything is not evidence
        # that a live mail domain publishes no SPF, DMARC and DKIM at once — that
        # combination is vanishingly rare, and reporting it filed three false criticals
        # against divii.ca (which has two SPF records and a DMARC policy). If every email
        # lookup is empty, treat DNS as unanswered and skip, rather than assert absence.
        if not spf_txt and not dmarc_txt and not any(dkim.values()):
            logger.warning(
                "domain_intel: SPF, DMARC and DKIM all returned empty for {} — treating as "
                "a failed lookup, not absence; skipping email findings this run.",
                apex,
            )
            raise _DnsUnanswered
        summary, email_findings = email_security.analyse(
            spf_txt=spf_txt, dmarc_txt=dmarc_txt, dkim_selectors=dkim
        )
        for ef in email_findings:
            findings.append(
                Finding(
                    tenant_id=tenant.tenant_id,
                    program_id=program_id,
                    fingerprint=finding_fingerprint(program_id, ef.check_id, apex),
                    check_id=ef.check_id,
                    module="domain_intel",
                    location=apex,
                    locator=ef.record,
                    name=ef.name,
                    description=ef.detail,
                    severity=ef.severity,
                    reproduction=f"dig +short TXT {apex} && dig +short TXT _dmarc.{apex}",
                    raw={"record": ef.record, "remediation": ef.remediation, "kind": "email"},
                )
            )
        if summary.get("spoofable"):
            logger.info("domain_intel: {} can be spoofed (no enforcing DMARC)", apex)
    except _DnsUnanswered:
        pass  # already logged; no findings rather than false "no record" findings
    except Exception as exc:  # noqa: BLE001 - DNS trouble must not sink the stage
        logger.warning("domain_intel: email assessment failed for {}: {}", apex, exc)

    # -- registration facts
    intel = None
    try:
        kwargs = {"fetch": rdap_fetch} if rdap_fetch else {}
        intel, domain_findings = await rdap.lookup(apex, **kwargs)
        for df in domain_findings:
            findings.append(
                Finding(
                    tenant_id=tenant.tenant_id,
                    program_id=program_id,
                    fingerprint=finding_fingerprint(program_id, df.check_id, apex),
                    check_id=df.check_id,
                    module="domain_intel",
                    location=apex,
                    name=df.name,
                    description=df.detail,
                    severity=df.severity,
                    reproduction=f"curl -s https://rdap.org/domain/{apex} | jq",
                    raw={"remediation": df.remediation, "kind": "registration"},
                )
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning("domain_intel: RDAP lookup failed for {}: {}", apex, exc)

    total, new = await FindingRepo.from_mongo(mongo).upsert_many(findings)

    registration = (
        {
            "registrar": intel.registrar,
            "created_at": intel.created_at.isoformat() if intel.created_at else None,
            "expires_at": intel.expires_at.isoformat() if intel.expires_at else None,
            "days_to_expiry": intel.days_to_expiry,
            "statuses": list(intel.statuses),
            "nameservers": list(intel.nameservers),
            "dnssec": intel.dnssec,
            "transfer_locked": intel.transfer_locked,
        }
        if intel
        else {}
    )
    # Persist the posture itself, not just the findings it produced: "DMARC is none"
    # and "expires in 214 days" are state the UI shows as a panel.
    await DomainIntelRepo.from_mongo(mongo).save(
        tenant.tenant_id, program_id, email=summary, registration=registration
    )
    logger.info(
        "domain_intel {}: spoofable={} expires_in={} → {} finding(s), {} new",
        apex,
        summary.get("spoofable"),
        intel.days_to_expiry if intel else "?",
        total,
        new,
    )
    return {
        "findings": total,
        "new": new,
        "spoofable": bool(summary.get("spoofable")),
        "days_to_expiry": (intel.days_to_expiry if intel else None),
        # Surfaced verbatim in the UI so the user sees the raw records, not a verdict.
        "email": summary,
        "registration": registration,
    }


class _DnsUnanswered(Exception):
    """DNS returned nothing for any email record — a failed lookup, not proof of absence."""


async def _default_resolve_txt(hostname: str) -> list[str]:  # pragma: no cover - real DNS
    """TXT lookup via dnsx (already in the image). Retries on an empty/failed result:
    dnsx is flaky under load, and an empty answer for a record that exists is exactly
    what produced false 'no SPF/DMARC' findings."""
    import asyncio

    from modules.recon.dnsx import resolve_txt_records

    for attempt in range(3):
        try:
            out = await resolve_txt_records(hostname)
        except Exception:  # noqa: BLE001
            out = []
        if out:
            return out
        if attempt < 2:
            await asyncio.sleep(1.0)
    return []
