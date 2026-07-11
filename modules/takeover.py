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

    async with aiohttp.ClientSession() as session:
        async with session.get(
            url, timeout=aiohttp.ClientTimeout(total=10), ssl=False, allow_redirects=True
        ) as resp:
            raw = await resp.content.read(1_000_000)
            return raw.decode("utf-8", errors="ignore")


def _match_service(cname: str) -> Service | None:
    c = cname.lower().rstrip(".")
    for svc in SERVICES:
        if any(marker in c for marker in svc.cname_markers):
            return svc
    return None


async def check_host(
    host: str,
    cnames: list[str],
    *,
    fetch: Fetch,
    resolve: Resolve | None = None,
) -> dict | None:
    """Return a takeover finding for *host* if one of its *cnames* points at an
    unclaimed known service, else ``None``.

    ``fetch(url) -> body`` retrieves the page (empty string on failure); ``resolve``
    (optional) resolves the CNAME target so a dangling (NXDOMAIN) record can be
    flagged for services where that means the name is claimable."""
    for cname in cnames:
        svc = _match_service(cname)
        if svc is None:
            continue

        # 1) HTTP fingerprint — the strong, confirmable signal.
        if svc.fingerprints:
            for scheme in ("https", "http"):
                body = ""
                try:
                    body = await fetch(f"{scheme}://{host}")
                except Exception:  # noqa: BLE001 - a fetch failure is not a finding
                    body = ""
                if body and any(fp in body for fp in svc.fingerprints):
                    return {
                        "host": host,
                        "service": svc.name,
                        "cname": cname,
                        "evidence": next(fp for fp in svc.fingerprints if fp in body),
                        "signal": "http-fingerprint",
                    }

        # 2) Dangling target — the CNAME resolves to nothing on a claimable service.
        if svc.nxdomain_takeover and resolve is not None:
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
    return None
