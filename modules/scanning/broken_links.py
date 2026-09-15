"""Broken-link hijacking — dead outbound links an attacker can take over.

A page links out to a domain or social handle that no longer exists. Anyone can
register that domain (or claim that handle) and instantly inherit the trust of the
page linking to it: the link still says "our partner", "our docs", "follow us", but now
points at attacker-controlled content. It is used for phishing, for malware delivery
with a trusted referrer, and — when the dead link is a script src — for straight code
execution in the victim's browser.

It is rarely scanned for, because finding it means crawling outbound links and checking
each destination's *availability*, not its content. That makes it a genuinely
differentiating check, and a purely passive one: we resolve names and read status
codes; we never register anything and never exploit.

Pure module — resolution and fetching are injected.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from urllib.parse import urlsplit

from core.severity import Severity

#: Public suffixes that take two labels, so the registrable domain is the last three
#: (foo.co.uk, not co.uk). Not exhaustive — the common ones — and erring toward treating
#: something as its own apex is the safe direction here: it means *fewer* hijack claims,
#: never a false one.
_TWO_LABEL_SUFFIXES: frozenset[str] = frozenset(
    """co.uk org.uk gov.uk ac.uk com.au net.au org.au co.nz com.br com.mx co.in co.jp
    co.za com.sg com.hk co.kr com.tr com.ua co.il com.cn""".split()
)

#: A label is a real DNS label: letters/digits/hyphen, not starting or ending in a
#: hyphen, non-empty. Rejects the JS fragments the miner sometimes yields
#: (e.g. "northamerica-northeast1-", which has an empty final label).
import re as _re  # noqa: E402

_LABEL = _re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", _re.I)


def registrable_domain(host: str) -> str | None:
    """The domain someone could actually register — eTLD+1 — or None if *host* is not a
    valid registrable name.

    A dangling *subdomain* (js.stripe.com) is a takeover, handled elsewhere; it is not a
    broken-link hijack, because you cannot register js.stripe.com — only stripe.com, and
    that is owned. So this collapses every host to its registrable apex, and the
    unregistered-domain check runs on *that*. It also rejects non-domains outright.
    """
    host = (host or "").strip().rstrip(".").lower()
    if not host or ".." in host:
        return None
    labels = host.split(".")
    if len(labels) < 2 or any(not _LABEL.match(x) for x in labels):
        return None
    if len(labels) >= 3 and ".".join(labels[-2:]) in _TWO_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


#: Platforms where a 404 on a profile URL means the handle is claimable by anyone.
#: Each entry: (host suffix, path depth that identifies a profile, human name).
SOCIAL_PLATFORMS: tuple[tuple[str, str], ...] = (
    ("twitter.com", "X/Twitter"),
    ("x.com", "X/Twitter"),
    ("instagram.com", "Instagram"),
    ("t.me", "Telegram"),
    ("medium.com", "Medium"),
    ("github.com", "GitHub"),
    ("gitlab.com", "GitLab"),
    ("youtube.com", "YouTube"),
    ("tiktok.com", "TikTok"),
    ("facebook.com", "Facebook"),
    ("slideshare.net", "SlideShare"),
    ("bitbucket.org", "Bitbucket"),
    ("npmjs.com", "npm"),
    ("hub.docker.com", "Docker Hub"),
)

#: Hosts that always resolve and are never hijackable — skip to save requests.
_SKIP_HOSTS: frozenset[str] = frozenset(
    {"localhost", "example.com", "example.org", "example.net", "w3.org", "schema.org"}
)


@dataclass(frozen=True)
class BrokenLink:
    """One hijackable outbound reference."""

    url: str  # the dead destination
    found_on: str  # the page (or JS file) that links to it
    kind: str  # "unregistered-domain" | "claimable-handle"
    platform: str | None  # for handles: which service
    evidence: str
    severity: Severity
    #: For an unregistered-domain finding: the registrable apex that is actually free
    #: (stripe.com, not js.stripe.com). None for a claimable-handle finding.
    apex: str | None = None

    @property
    def target_host(self) -> str:
        return urlsplit(self.url).hostname or ""


Resolve = Callable[[str], Awaitable[list[str]]]
FetchStatus = Callable[[str], Awaitable[int]]


def is_external(url: str, own_domains: tuple[str, ...]) -> bool:
    """True when *url* points outside the operator's own domains."""
    host = (urlsplit(url).hostname or "").lower()
    if not host or host in _SKIP_HOSTS:
        return False
    return not any(host == d or host.endswith("." + d) for d in own_domains)


def social_platform(url: str) -> str | None:
    """The platform name if this URL is a claimable profile link, else None.

    Requires an actual handle segment: ``twitter.com/acme`` is a profile,
    ``twitter.com`` alone is not, and deep links like ``/acme/status/123`` are content
    rather than an ownable identity.
    """
    parts = urlsplit(url)
    host = (parts.hostname or "").lower().removeprefix("www.")
    segments = [s for s in parts.path.split("/") if s]
    if len(segments) != 1:
        return None
    handle = segments[0].lower()
    # Reserved/system paths are not handles.
    if handle in {"about", "help", "terms", "privacy", "login", "signup", "home", "explore"}:
        return None
    for suffix, name in SOCIAL_PLATFORMS:
        if host == suffix or host.endswith("." + suffix):
            return name
    return None


async def check_link(
    url: str,
    found_on: str,
    *,
    resolve: Resolve,
    fetch_status: FetchStatus | None = None,
) -> BrokenLink | None:
    """Classify one outbound link. Returns a finding only when it is genuinely takeable.

    Two signals, in order of confidence:

    1. **The host does not resolve at all.** For a link that a live page publishes, that
       almost always means the domain lapsed — it is registerable today.
    2. **A social profile returns 404.** The handle was deleted or renamed, so anyone can
       claim it and speak as the company.
    """
    host = urlsplit(url).hostname
    if not host:
        return None

    # Only the registrable apex is takeable. js.stripe.com not resolving does not make
    # anything registerable — stripe.com is owned. Check the apex, and skip non-domains.
    apex = registrable_domain(host)
    if apex:
        try:
            addresses = await resolve(apex)
        except Exception:  # noqa: BLE001 - a resolver error is not evidence of anything
            return None

        # Empty means the resolver POSITIVELY confirmed the apex does not exist
        # (NXDOMAIN). A failed or timed-out lookup raises above and yields nothing —
        # absence of an answer is never treated as absence of the domain, which is what
        # once flagged js.stripe.com and api-iam.intercom.io as hijackable.
        if not addresses:
            return BrokenLink(
                url=url,
                found_on=found_on,
                kind="unregistered-domain",
                platform=None,
                evidence=f"{apex} returns NXDOMAIN — the registrable domain does not "
                "exist and can be registered by anyone, who would then control every link "
                f"to it (seen here as {host}).",
                severity=Severity.HIGH,
                apex=apex,
            )

    platform = social_platform(url)
    if platform and fetch_status is not None:
        try:
            status = await fetch_status(url)
        except Exception:  # noqa: BLE001
            return None
        if status == 404:
            return BrokenLink(
                url=url,
                found_on=found_on,
                kind="claimable-handle",
                platform=platform,
                evidence=f"The {platform} profile returns 404 — the handle is unclaimed, "
                "so anyone can register it and post as this brand from a link you publish.",
                severity=Severity.MEDIUM,
            )
    return None


def remediation(link: BrokenLink) -> str:
    if link.kind == "unregistered-domain":
        return (
            f"Remove or update the link to {link.target_host} on {link.found_on}. If the "
            "domain was yours, re-register it; if it belonged to a partner, point the link "
            "somewhere you control."
        )
    return (
        f"Remove the dead {link.platform} link on {link.found_on}, or claim the handle "
        "yourself so nobody else can."
    )
