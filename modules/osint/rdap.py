"""Domain registration intelligence via RDAP (the modern, JSON replacement for WHOIS).

The first thing an attacker learns about a target is who owns the domain, when it
expires, and whether it is locked. Two of those are exploitable:

* **An expiring domain** can be re-registered by anyone the moment it drops — that is a
  total takeover of the brand, its mail, and every service authenticated against it.
  Nobody notices until it happens, because the expiry lives in a registrar account the
  security team usually cannot see.
* **A domain without a transfer lock** is one successful registrar-account phish away
  from being moved to an attacker.

RDAP is used rather than legacy WHOIS because it returns structured JSON over HTTPS —
no per-registrar text scraping, and no rate-limited port 43. Parsing is pure and
tested; the fetch is injected so this module stays offline-testable.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from core.severity import Severity

#: rdap.org bootstraps to the authoritative registry for any TLD, so one URL works.
RDAP_BASE = "https://rdap.org/domain/"

#: EPP status codes that mean "this domain cannot be silently transferred away".
_LOCK_STATUSES = ("clienttransferprohibited", "servertransferprohibited")

#: Expiry thresholds. Under 30 days is an emergency; under 90 is worth planning for.
EXPIRY_CRITICAL_DAYS = 30
EXPIRY_WARNING_DAYS = 90


@dataclass(frozen=True)
class DomainIntel:
    """What registration data tells us. All fields optional — registries vary."""

    domain: str
    registrar: str | None = None
    created_at: datetime | None = None
    expires_at: datetime | None = None
    updated_at: datetime | None = None
    statuses: tuple[str, ...] = ()
    nameservers: tuple[str, ...] = ()
    dnssec: bool = False

    @property
    def days_to_expiry(self) -> int | None:
        if self.expires_at is None:
            return None
        return (self.expires_at - datetime.now(UTC)).days

    @property
    def transfer_locked(self) -> bool:
        return any(s.replace(" ", "").lower() in _LOCK_STATUSES for s in self.statuses)


@dataclass(frozen=True)
class DomainFinding:
    check_id: str
    name: str
    severity: Severity
    detail: str
    remediation: str


def _parse_date(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def parse_rdap(domain: str, payload: dict) -> DomainIntel:
    """Turn an RDAP response into :class:`DomainIntel`. Tolerant by design — registries
    differ in which optional blocks they return, and a missing field is not an error."""
    events = {
        (e.get("eventAction") or "").lower(): e.get("eventDate")
        for e in payload.get("events", [])
        if isinstance(e, dict)
    }

    registrar = None
    for entity in payload.get("entities", []) or []:
        if not isinstance(entity, dict):
            continue
        if "registrar" in [r.lower() for r in entity.get("roles", []) or []]:
            # vCard: ["vcard", [["version",...], ["fn", {}, "text", "Registrar Name"], ...]]
            vcard = (entity.get("vcardArray") or [None, []])[1]
            for item in vcard:
                if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                    registrar = str(item[3])
                    break
            if registrar:
                break

    nameservers = tuple(
        str(ns.get("ldhName", "")).lower()
        for ns in payload.get("nameservers", []) or []
        if isinstance(ns, dict) and ns.get("ldhName")
    )
    secure_dns = payload.get("secureDNS") or {}

    return DomainIntel(
        domain=domain,
        registrar=registrar,
        created_at=_parse_date(events.get("registration")),
        expires_at=_parse_date(events.get("expiration")),
        updated_at=_parse_date(events.get("last changed") or events.get("last update")),
        statuses=tuple(str(s) for s in payload.get("status", []) or []),
        nameservers=nameservers,
        dnssec=bool(secure_dns.get("delegationSigned")),
    )


def assess(intel: DomainIntel) -> list[DomainFinding]:
    """Findings derived from registration state."""
    out: list[DomainFinding] = []
    days = intel.days_to_expiry

    if days is not None and days < 0:
        out.append(
            DomainFinding(
                "domain-expired",
                f"Domain registration EXPIRED {abs(days)} days ago",
                Severity.CRITICAL,
                "The registration lapsed. Once it leaves the redemption period anyone can "
                "register it and instantly control the website, the mail, and any service "
                "that trusts this domain.",
                "Renew with the registrar immediately — this is time-critical.",
            )
        )
    elif days is not None and days <= EXPIRY_CRITICAL_DAYS:
        out.append(
            DomainFinding(
                "domain-expiring-critical",
                f"Domain expires in {days} days",
                Severity.HIGH,
                "If this lapses, the domain can be re-registered by anyone — a complete "
                "takeover of the brand, its email, and every login that depends on it.",
                "Renew now and enable auto-renew at the registrar.",
            )
        )
    elif days is not None and days <= EXPIRY_WARNING_DAYS:
        out.append(
            DomainFinding(
                "domain-expiring-soon",
                f"Domain expires in {days} days",
                Severity.LOW,
                "Not urgent yet, but domain expiry is a single point of total failure and "
                "is usually invisible to the security team.",
                "Confirm auto-renew is on and the registrar's billing contact is current.",
            )
        )

    if intel.statuses and not intel.transfer_locked:
        out.append(
            DomainFinding(
                "domain-no-transfer-lock",
                "Domain has no registrar transfer lock",
                Severity.MEDIUM,
                "clientTransferProhibited is not set, so a compromised or socially-"
                "engineered registrar account can move the domain to an attacker without "
                "the extra barrier a lock provides.",
                "Enable the transfer lock (and 2FA) in your registrar account.",
            )
        )

    if not intel.dnssec:
        out.append(
            DomainFinding(
                "domain-no-dnssec",
                "DNSSEC is not enabled",
                Severity.INFO,
                "Without DNSSEC, DNS answers for this domain are not cryptographically "
                "signed, leaving more room for spoofing and cache-poisoning attacks.",
                "Enable DNSSEC at your registrar/DNS provider if your setup supports it.",
            )
        )
    return out


Fetch = Callable[[str], Awaitable[dict]]


async def default_fetch(url: str) -> dict:  # pragma: no cover - real network
    """Fetch RDAP JSON through the SSRF-safe guarded session."""
    import aiohttp

    from modules.safe_http import assert_url_allowed, guarded_session

    assert_url_allowed(url)
    async with guarded_session() as session:
        async with session.get(
            url,
            timeout=aiohttp.ClientTimeout(total=20),
            headers={"Accept": "application/rdap+json"},
            allow_redirects=False,
        ) as resp:
            if resp.status != 200:
                return {}
            return await resp.json(content_type=None)


async def lookup(
    domain: str, *, fetch: Fetch = default_fetch
) -> tuple[DomainIntel | None, list[DomainFinding]]:
    """Look a domain up and assess it. A failed lookup yields no findings rather than a
    false alarm — an unreachable registry says nothing about the domain's security."""
    try:
        payload = await fetch(f"{RDAP_BASE}{domain}")
    except Exception:  # noqa: BLE001 - registry outages must not fail a scan
        return None, []
    if not payload:
        return None, []
    intel = parse_rdap(domain, payload)
    return intel, assess(intel)
