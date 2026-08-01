"""Subdomain-takeover detection (module 19-ish).

A dangling DNS record — a CNAME pointing at a de-provisioned cloud service — lets an
attacker re-claim that service and serve content from *your* subdomain. We already
harvest CNAMEs (dnsx recon), so detection is: match the CNAME target to a known
service, then confirm the service is unclaimed either by an HTTP "not found"
fingerprint or (for services where it applies) an NXDOMAIN/dangling target.

Fingerprints are a curated subset of the community `can-i-take-over-xyz` catalogue —
the high-signal, HTTP-confirmable ones, so a finding means "very likely takeoverable",
not just "points at a cloud service".
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass

Fetch = Callable[[str], Awaitable[str]]
Resolve = Callable[[str], Awaitable[list[str]]]


@dataclass(frozen=True)
class Service:
    name: str
    cname_markers: tuple[str, ...]  # substrings that identify the CNAME target
    fingerprints: tuple[str, ...]  # response body strings that mean "unclaimed"
    nxdomain_takeover: bool = False  # a dangling (NXDOMAIN) target is claimable


#: high-signal, HTTP-confirmable services (curated from can-i-take-over-xyz).
SERVICES: tuple[Service, ...] = (
    Service(
        "AWS/S3",
        ("s3.amazonaws.com", "s3-website", "s3.", ".s3-"),
        ("NoSuchBucket", "The specified bucket does not exist"),
    ),
    Service(
        "GitHub Pages",
        ("github.io", "githubusercontent"),
        (
            "There isn't a GitHub Pages site here",
            "For root URLs (like http://example.com/) you must provide an index.html file",
        ),
    ),
    Service(
        "Heroku",
        ("herokuapp.com", "herokudns.com", "herokussl.com"),
        ("No such app", "herokucdn.com/error-pages/no-such-app.html"),
        nxdomain_takeover=True,
    ),
    Service("Shopify", ("myshopify.com",), ("Sorry, this shop is currently unavailable",)),
    Service("Fastly", ("fastly.net",), ("Fastly error: unknown domain",)),
    Service("Zendesk", ("zendesk.com",), ("Help Center Closed",)),
    Service("Read the Docs", ("readthedocs.io", "readthedocs.org"), ("unknown to Read the Docs",)),
    Service("Bitbucket", ("bitbucket.io",), ("Repository not found",)),
    Service("Ghost", ("ghost.io",), ("The thing you were looking for is no longer here",)),
    Service("Surge.sh", ("surge.sh",), ("project not found",)),
    Service(
        "Pantheon",
        ("pantheonsite.io",),
        ("The gods are wise, but do not know of the site which you seek",),
    ),
    Service(
        "Tumblr",
        ("domains.tumblr.com",),
        ("Whatever you were looking for doesn't currently exist at this address",),
    ),
    Service("WordPress", ("wordpress.com",), ("Do you want to register",)),
    Service("Cargo", ("cargocollective.com",), ("<title>404 &mdash; File not found",)),
    Service("Wix", ("wixdns.net", "wix.com"), ("Error ConnectYourDomain occurred",)),
    Service(
        "Azure",
        (
            "azurewebsites.net",
            "cloudapp.net",
            "trafficmanager.net",
            "blob.core.windows.net",
            "azureedge.net",
        ),
        (),
        nxdomain_takeover=True,
    ),
)


async def default_fetch(url: str) -> str:  # pragma: no cover - real network
    import aiohttp

    from modules.safe_http import assert_url_allowed, guarded_session

    # SSRF guard: never let a takeover probe be redirected/rebound to an internal
    # address (e.g. the cloud metadata endpoint). Redirects are off and the resolver
    # blocks non-public IPs — see modules.safe_http (§3.10).
    assert_url_allowed(url)
    async with guarded_session() as session:
        async with session.get(
            url, timeout=aiohttp.ClientTimeout(total=10), ssl=False, allow_redirects=False
        ) as resp:
            raw = await resp.content.read(1_000_000)
            return raw.decode("utf-8", errors="ignore")


def _match_service(cname: str) -> Service | None:
    c = cname.lower().rstrip(".")
    for svc in SERVICES:
        if any(marker in c for marker in svc.cname_markers):
            return svc
    return None


def _fingerprint_in(body: str) -> tuple[Service, str] | None:
    """First (service, fingerprint) whose unclaimed-marker appears in *body*."""
    for svc in SERVICES:
        for fp in svc.fingerprints:
            if fp in body:
                return svc, fp
    return None


async def check_host(
    host: str,
    cnames: list[str],
    *,
    fetch: Fetch,
    resolve: Resolve | None = None,
) -> dict | None:
    """Return a takeover finding for *host* if it looks claimable, else ``None``.

    Two signals: (1) a dangling CNAME to a claimable service that no longer resolves
    (NXDOMAIN), and (2) an HTTP "unclaimed" fingerprint in the response body. The body
    is scanned against EVERY service's fingerprints regardless of the CNAME target —
    crucial for S3 fronted by CloudFront, where the CNAME is ``*.cloudfront.net`` but
    the body is S3's ``NoSuchBucket`` (a CNAME-only match would miss it)."""
    # 1) Dangling CNAME (NXDOMAIN) for claimable services — cheap, no fetch.
    for cname in cnames:
        svc = _match_service(cname)
        if svc and svc.nxdomain_takeover and resolve is not None:
            try:
                ips = await resolve(cname)
            except Exception:  # noqa: BLE001
                ips = ["_"]  # treat resolver errors as "resolved" (no finding)
            if not ips:
                return {
                    "host": host,
                    "service": svc.name,
                    "cname": cname,
                    "evidence": f"CNAME {cname} does not resolve (dangling)",
                    "signal": "nxdomain",
                }

    # 2) HTTP fingerprint — fetch the body once and scan it against ALL services.
    for scheme in ("https", "http"):
        try:
            body = await fetch(f"{scheme}://{host}")
        except Exception:  # noqa: BLE001 - a fetch failure is not a finding
            body = ""
        if not body:
            continue
        match = _fingerprint_in(body)
        if match:
            svc, fp = match
            # attribute to the CNAME that points at this service, else the first CNAME.
            cname = next(
                (c for c in cnames if _match_service(c) is svc), cnames[0] if cnames else ""
            )
            return {
                "host": host,
                "service": svc.name,
                "cname": cname,
                "evidence": fp,
                "signal": "http-fingerprint",
            }
        break  # got a real body on https; a live/other page is not a takeover
    return None


# -- dangling A-records to unclaimed cloud IPs -------------------------------
# Same vulnerability class as a dangling CNAME, different record type. A name that
# points into a cloud provider's address space at an instance that no longer exists is
# claimable by whoever next receives that address from the provider's pool.
#
# This is deliberately reported at a LOWER confidence than a CNAME takeover, and the
# reason matters: with a CNAME you can usually claim the exact target on demand, while
# an elastic IP is drawn from a pool and getting a specific one back is opportunistic.
# The exposure is real — it has been used — but calling it Critical would be inflating
# it, and this product's severities are supposed to mean something.

#: IP classes that indicate provider-pooled address space.
_POOLED_CLASSES = ("cloud_shared", "cdn")


@dataclass(frozen=True)
class DanglingRecord:
    """A hostname whose A record points into cloud space with nothing behind it."""

    host: str
    ip: str
    ip_class: str
    reason: str

    @property
    def evidence(self) -> str:
        return (
            f"{self.host} resolves to {self.ip}, which sits in provider-pooled address "
            f"space ({self.ip_class}), but {self.reason}. When a cloud instance is "
            "destroyed its address returns to the provider's pool; anyone who later "
            "receives that address serves content from your hostname until the DNS "
            "record is removed."
        )

    @property
    def remediation(self) -> str:
        return (
            f"Delete the A record for {self.host} if the resource behind it is gone, or "
            "point it at a resource you still control. For anything long-lived, prefer "
            "an allocated static address or an alias/CNAME to a named provider resource "
            "rather than a raw IP, so a destroyed instance cannot orphan the name."
        )


def find_dangling_a_records(
    assets: list[dict],
    *,
    classify,
    alive_hosts: set[str],
) -> list[DanglingRecord]:
    """Hostnames pointing at pooled cloud IPs with nothing answering.

    ``classify(ip)`` returns the ``IpClass`` value for an address (the scope engine
    already computes this). ``alive_hosts`` is the set of hostnames the probe stage
    confirmed responding — anything in it is serving traffic and is not dangling,
    whatever its address class.

    Pure: takes the data and returns verdicts, so the rules are testable without DNS.
    """
    out: list[DanglingRecord] = []
    seen: set[str] = set()
    for asset in assets:
        host = (asset.get("hostname") or "").lower()
        if not host or host in seen or host in alive_hosts:
            continue
        if not asset.get("monitored", True):
            continue
        records = asset.get("dns_records") or {}
        # A CNAME present means the CNAME path already covers it; do not double-report.
        if records.get("cname"):
            continue
        for ip in asset.get("resolved_ips") or []:
            try:
                ip_class = str(classify(ip))
            except Exception:  # noqa: BLE001, S112 - an unclassifiable address is
                continue  # simply not evidence of anything; the next one still runs
            if ip_class not in _POOLED_CLASSES:
                continue
            seen.add(host)
            out.append(
                DanglingRecord(
                    host=host,
                    ip=ip,
                    ip_class=ip_class,
                    reason="nothing answered on it during this scan",
                )
            )
            break
    return out
