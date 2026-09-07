"""Central scope-enforcement engine — the most important control in ExactSurface.

Every module that touches the network MUST route its target through this engine
before any I/O. The rule is enforced by convention *and* by code review: a
network call that does not first obtain a permissive :class:`ScopeDecision` is a
defect.

The engine is deliberately **pure** (no DNS, no sockets, no database). It takes
already-resolved inputs and returns a decision. The async convenience wrapper
:func:`assert_in_scope` accepts an injected resolver so that DNS resolution
happens outside this module and the decision logic stays fully unit-testable
with zero I/O.

Guarantees (proven by tests in ``tests/unit/test_scope.py``):

* Private, loopback, link-local (incl. the cloud metadata IP 169.254.169.254),
  CGNAT, multicast, and reserved addresses are **always denied**, with no
  override — even if a verified subdomain resolves to one (DNS-rebinding guard).
* A host that is not a subdomain of a verified program apex is denied.
* A host on the program's exclusion list is denied.
* CDN / cloud-shared IPs are permitted **HTTP-layer probing only**; port
  scanning, content discovery, and active scanning are withheld unless every
  resolved IP is confirmed dedicated to the operator.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from enum import Enum
from functools import lru_cache
from pathlib import Path

from core.errors import OutOfScope

_DATA_FILE = Path(__file__).parent / "data" / "cloud_ranges.json"


class IpClass(str, Enum):
    """Classification of a resolved IP address."""

    DEDICATED = "dedicated"  # confirmed owned/authorised (decided in evaluate)
    CDN = "cdn"  # shared CDN edge (Cloudflare/Akamai/Fastly/CloudFront/...)
    CLOUD_SHARED = "cloud_shared"  # generic shared cloud range
    PUBLIC = "public"  # routable, ownership unconfirmed
    PRIVATE = "private"
    LOOPBACK = "loopback"
    LINK_LOCAL = "link_local"  # 169.254.0.0/16 — includes metadata 169.254.169.254
    CGNAT = "cgnat"  # 100.64.0.0/10
    MULTICAST = "multicast"
    RESERVED = "reserved"
    UNSPECIFIED = "unspecified"


#: IP classes that can never be scanned, under any circumstance or override.
HARD_DENY: frozenset[IpClass] = frozenset(
    {
        IpClass.PRIVATE,
        IpClass.LOOPBACK,
        IpClass.LINK_LOCAL,
        IpClass.CGNAT,
        IpClass.MULTICAST,
        IpClass.RESERVED,
        IpClass.UNSPECIFIED,
    }
)

#: IP classes that are reachable but only over the HTTP layer (never port/active).
HTTP_ONLY_CLASSES: frozenset[IpClass] = frozenset(
    {IpClass.CDN, IpClass.CLOUD_SHARED, IpClass.PUBLIC}
)


class Action(str, Enum):
    """A capability a module may want to exercise against a target."""

    PASSIVE_RECON = "passive_recon"  # no direct contact (crt.sh, wayback, uncover)
    HTTP_PROBE = "http_probe"  # httpx alive-check / header analysis
    TLS_INSPECT = "tls_inspect"  # tlsx cert inspection
    PORT_SCAN = "port_scan"  # naabu / nmap
    CONTENT_DISCOVERY = "content_discovery"  # feroxbuster / ffuf
    ACTIVE_SCAN = "active_scan"  # nuclei active templates beyond safe-passive


#: The full action set granted to confirmed-dedicated, in-scope hosts.
FULL_ACTIONS: frozenset[Action] = frozenset(Action)

#: HTTP-layer-only set granted to CDN/cloud-shared/unconfirmed public hosts.
HTTP_LAYER_ACTIONS: frozenset[Action] = frozenset(
    {Action.PASSIVE_RECON, Action.HTTP_PROBE, Action.TLS_INSPECT}
)


@dataclass(frozen=True)
class ProgramScope:
    """The authorised scope of one program, as confirmed at onboarding.

    ``authorized_dedicated_cidrs`` is populated only after WHOIS/ASN ownership is
    confirmed (see §9b of the spec). Until an IP falls inside one of these
    ranges it is treated as unconfirmed and gets HTTP-layer access only.
    """

    verified_apexes: tuple[str, ...]
    excluded_hosts: frozenset[str] = frozenset()
    excluded_cidrs: tuple[str, ...] = ()
    authorized_dedicated_cidrs: tuple[str, ...] = ()
    #: When the operator explicitly attests they own the cloud infra their domain
    #: runs on (§9b), grant the full action set to CLOUD_SHARED/PUBLIC IPs too — so
    #: ports/content/active-scan run on their own AWS/GCP/Azure assets. Third-party
    #: CDN edges (Cloudflare/Akamai/Fastly) and every HARD_DENY class stay locked.
    scan_shared_infra: bool = False

    def owns_host(self, host: str) -> bool:
        h = host.lower().rstrip(".")
        for apex in self.verified_apexes:
            a = apex.lower().rstrip(".")
            if h == a or h.endswith("." + a):
                return True
        return False


@dataclass(frozen=True)
class ScopeDecision:
    """The verdict returned for one (host, resolved IPs) evaluation."""

    host: str
    allowed: bool
    reason: str
    ip_class: IpClass | None = None
    actions: frozenset[Action] = field(default_factory=frozenset)

    def permits(self, action: Action) -> bool:
        return self.allowed and action in self.actions

    def require(self, action: Action) -> None:
        """Raise :class:`OutOfScope` unless *action* is permitted."""
        if not self.allowed:
            raise OutOfScope(self.host, self.reason)
        if action not in self.actions:
            raise OutOfScope(
                self.host,
                f"action {action.value!r} not permitted for ip_class="
                f"{self.ip_class.value if self.ip_class else 'n/a'}",
            )


def _parse_networks(cidrs: tuple[str, ...] | list[str]):
    nets = []
    for cidr in cidrs:
        try:
            nets.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            continue
    return nets


#: Marker prefix written into ``IpScopeEntry.confirmed_via`` when — and only when —
#: the server itself confirmed a CIDR against the apex's announced ASN ranges.
#: ``build_program_scope`` trusts nothing else, so a client-supplied string can
#: never promote a CIDR to DEDICATED (§9b step 3).
ASN_CONFIRMED_PREFIX = "asnmap:"
UNCONFIRMED = "unconfirmed"
PENDING = "pending"
CDN_NEVER_DEDICATED = "cdn_edge_never_dedicated"


def is_asn_confirmed(entry: dict) -> bool:
    """True only for an entry the server confirmed against real ASN data."""
    return str(entry.get("ip_class")) == IpClass.DEDICATED.value and str(
        entry.get("confirmed_via", "")
    ).startswith(ASN_CONFIRMED_PREFIX)


class ScopeEngine:
    """Holds the CDN/cloud feeds and evaluates scope decisions.

    Construct once and reuse. ``classify_ip`` and ``evaluate`` are pure — the
    same inputs always yield the same decision, which is what makes the safety
    guarantees testable.
    """

    def __init__(
        self,
        provider_ranges: dict[IpClass, list] | None = None,
        *,
        allow_private: bool = False,
    ) -> None:
        self._ranges: dict[IpClass, list] = provider_ranges or {}
        # LAB MODE (dev only): permit RFC1918 private targets so a local VM can be
        # scanned. Loopback, link-local/metadata, CGNAT, multicast, and reserved
        # stay denied even here. Prod refuses to enable this (Settings.assert_prod_safe).
        self._allow_private = allow_private

    # -- construction ----------------------------------------------------
    @classmethod
    def from_feed(cls, feed: dict, *, allow_private: bool = False) -> ScopeEngine:
        """Build from an in-memory feed dict (``{"providers": [...]}``).

        Pure — no I/O — so the feed can come from the bundled file, from Mongo, or
        from a test fixture without this module knowing or caring which. That is
        what lets the feed be distributed via Mongo (ADR-0014) while ``core`` stays
        dependency-free.
        """
        buckets: dict[IpClass, list] = {IpClass.CDN: [], IpClass.CLOUD_SHARED: []}
        for provider in feed.get("providers", []):
            cls_name = provider.get("class", "cdn")
            ip_class = IpClass.CDN if cls_name == "cdn" else IpClass.CLOUD_SHARED
            buckets[ip_class].extend(_parse_networks(provider.get("cidrs", [])))
        return cls(buckets, allow_private=allow_private)

    @classmethod
    def from_data_file(
        cls, path: Path | None = None, *, allow_private: bool = False
    ) -> ScopeEngine:
        path = path or _DATA_FILE
        return cls.from_feed(json.loads(path.read_text()), allow_private=allow_private)

    @staticmethod
    def bundled_feed() -> dict:
        """The feed shipped inside the image — the always-available fallback."""
        return json.loads(_DATA_FILE.read_text())

    # -- classification --------------------------------------------------
    def classify_ip(self, ip: str) -> IpClass:
        """Classify a single IP purely from its value and the loaded feeds.

        Never returns :attr:`IpClass.DEDICATED` — dedication is an ownership
        decision made in :meth:`evaluate`, not something an address reveals.
        """
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return IpClass.RESERVED  # unparseable → treat as hard-deny, fail closed

        if addr.is_unspecified:
            return IpClass.UNSPECIFIED
        if addr.is_loopback:
            return IpClass.LOOPBACK
        if addr.is_link_local:  # 169.254.0.0/16 and fe80::/10 — includes metadata IP
            return IpClass.LINK_LOCAL
        if addr.is_multicast:
            return IpClass.MULTICAST
        if addr.version == 4 and addr in ipaddress.ip_network("100.64.0.0/10"):
            return IpClass.CGNAT
        if addr.is_private:
            return IpClass.PRIVATE
        if addr.is_reserved:
            return IpClass.RESERVED

        # Routable public address: is it shared CDN / cloud infrastructure?
        for ip_class in (IpClass.CDN, IpClass.CLOUD_SHARED):
            for net in self._ranges.get(ip_class, ()):
                if addr.version == net.version and addr in net:
                    return ip_class
        return IpClass.PUBLIC

    # -- decision --------------------------------------------------------
    def evaluate(
        self,
        host: str,
        resolved_ips: list[str],
        scope: ProgramScope,
    ) -> ScopeDecision:
        """Return the scope verdict for *host* given its *resolved_ips*."""
        host_l = host.lower().rstrip(".")

        # 1. Host must belong to a verified program apex.
        if not scope.owns_host(host_l):
            return ScopeDecision(host_l, False, "host not under any verified apex")

        # 2. Explicit exclusion by host.
        if host_l in {h.lower().rstrip(".") for h in scope.excluded_hosts}:
            return ScopeDecision(host_l, False, "host on program exclusion list")

        if not resolved_ips:
            # No IPs to act against; passive recon only (nothing to contact).
            return ScopeDecision(
                host_l,
                True,
                "no resolved IPs; passive recon only",
                ip_class=None,
                actions=frozenset({Action.PASSIVE_RECON}),
            )

        excluded_nets = _parse_networks(scope.excluded_cidrs)
        dedicated_nets = _parse_networks(scope.authorized_dedicated_cidrs)

        classes: list[IpClass] = []
        all_dedicated = True
        for ip in resolved_ips:
            cls = self.classify_ip(ip)

            # 3. Any hard-deny IP poisons the whole host (DNS-rebinding guard).
            #    Lab mode is the ONE exception: RFC1918 private is allowed so a
            #    local VM can be scanned. Everything else stays hard-denied.
            lab_private = self._allow_private and cls == IpClass.PRIVATE
            if cls in HARD_DENY and not lab_private:
                return ScopeDecision(
                    host_l,
                    False,
                    f"resolves to non-routable/internal IP {ip} ({cls.value})",
                    ip_class=cls,
                )

            # 4. Explicit exclusion by CIDR.
            addr = ipaddress.ip_address(ip)
            if any(addr.version == n.version and addr in n for n in excluded_nets):
                return ScopeDecision(
                    host_l, False, f"IP {ip} on program CIDR exclusion list", ip_class=cls
                )

            # 5. Is this IP confirmed dedicated to the operator? (Lab-mode private counts.)
            #    scan_shared_infra opt-in extends "dedicated" to generic cloud/public
            #    IPs (NOT third-party CDN edges), for operators who own their cloud.
            shared_ok = scope.scan_shared_infra and cls in (
                IpClass.CLOUD_SHARED,
                IpClass.PUBLIC,
            )
            # A third-party CDN edge is NEVER promotable to dedicated, even if it
            # falls inside an authorized CIDR — that infrastructure belongs to
            # Cloudflare/Akamai/Fastly, not the operator (§9b). Defence in depth:
            # authorized_dedicated_cidrs should already be ASN-confirmed, but a bad
            # or stale entry must not unlock aggressive scanning of a CDN.
            in_dedicated_cidr = cls != IpClass.CDN and any(
                addr.version == n.version and addr in n for n in dedicated_nets
            )
            is_dedicated = lab_private or shared_ok or in_dedicated_cidr
            if is_dedicated:
                classes.append(IpClass.DEDICATED)
            else:
                classes.append(cls)
                all_dedicated = False

        if all_dedicated:
            return ScopeDecision(
                host_l,
                True,
                "all resolved IPs confirmed dedicated; full action set granted",
                ip_class=IpClass.DEDICATED,
                actions=FULL_ACTIONS,
            )

        # Mixed or shared/unconfirmed → HTTP-layer only, conservatively.
        representative = next((c for c in classes if c != IpClass.DEDICATED), IpClass.PUBLIC)
        return ScopeDecision(
            host_l,
            True,
            "IP(s) shared/unconfirmed; HTTP-layer probing only",
            ip_class=representative,
            actions=HTTP_LAYER_ACTIONS,
        )


@lru_cache(maxsize=1)
def default_engine() -> ScopeEngine:
    """Process-wide engine built from the bundled feed file.

    Honors ``EXACTSURFACE_LAB_ALLOW_PRIVATE`` (dev only) so a local VM can be scanned.
    """
    from core.config import get_settings

    return ScopeEngine.from_data_file(allow_private=get_settings().lab_allow_private)


def classify_ip(ip: str) -> IpClass:
    """Module-level convenience over :meth:`ScopeEngine.classify_ip`."""
    return default_engine().classify_ip(ip)


async def assert_in_scope(
    host: str,
    scope: ProgramScope,
    resolver,
    engine: ScopeEngine | None = None,
) -> ScopeDecision:
    """Resolve *host* via the injected *resolver* and enforce scope.

    ``resolver`` is any async callable ``(host) -> list[str]`` of IP strings.
    Injecting it keeps DNS out of this pure module and lets tests pass a stub.
    Raises :class:`OutOfScope` if the host is not allowed at all; otherwise
    returns the :class:`ScopeDecision` describing which actions are permitted.
    """
    engine = engine or default_engine()
    ips = list(await resolver(host))
    decision = engine.evaluate(host, ips, scope)
    if not decision.allowed:
        raise OutOfScope(decision.host, decision.reason)
    return decision


def confirm_ip_scope(
    requested_cidrs: list[str],
    apex_asn_ranges: list[str],
    *,
    engine: ScopeEngine | None = None,
) -> list[dict]:
    """Decide, **server-side**, what each requested CIDR is actually allowed (§9b step 3).

    An operator proving DNS control over an apex does not authorise scanning every
    IP that apex's subdomains resolve to. So the client only ever *requests* CIDRs;
    this function assigns the class, action set, and ``confirmed_via`` — the client
    never supplies them.

    A CIDR is promoted to ``DEDICATED`` (full actions) only when it sits inside a
    range genuinely announced by the ASN behind the operator's verified apex
    (*apex_asn_ranges*, from ``asnmap``). Otherwise it stays HTTP-layer only.
    Non-routable/internal ranges are rejected outright, and a CDN edge is never
    dedicated even if the ASN matches — that range belongs to the CDN.

    Returns ``IpScopeEntry``-shaped dicts. Invalid CIDRs are dropped.
    """
    engine = engine or default_engine()
    apex_nets = _parse_networks(apex_asn_ranges)
    out: list[dict] = []

    for cidr in requested_cidrs:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue  # not a CIDR — silently dropped rather than trusted

        cls = engine.classify_ip(str(net.network_address))
        if cls in HARD_DENY:
            continue  # never authorisable, at any tier — don't even record it

        containing = next(
            (n for n in apex_nets if n.version == net.version and net.subnet_of(n)),
            None,
        )
        if cls == IpClass.CDN:
            decided_class, actions, via = cls, HTTP_LAYER_ACTIONS, CDN_NEVER_DEDICATED
        elif containing is not None:
            decided_class, actions, via = (
                IpClass.DEDICATED,
                FULL_ACTIONS,
                f"{ASN_CONFIRMED_PREFIX}{containing}",
            )
        else:
            decided_class, actions, via = cls, HTTP_LAYER_ACTIONS, UNCONFIRMED

        out.append(
            {
                "cidr": str(net),
                "ip_class": decided_class.value,
                "action_set": sorted(a.value for a in actions),
                "confirmed_via": via,
            }
        )
    return out
