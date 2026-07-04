"""Central scope-enforcement engine — the most important control in Vantari.

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
  resolved IP is confirmed dedicated to the customer.
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


class ScopeEngine:
    """Holds the CDN/cloud feeds and evaluates scope decisions.

    Construct once and reuse. ``classify_ip`` and ``evaluate`` are pure — the
    same inputs always yield the same decision, which is what makes the safety
    guarantees testable.
    """

    def __init__(self, provider_ranges: dict[IpClass, list] | None = None) -> None:
        self._ranges: dict[IpClass, list] = provider_ranges or {}

    # -- construction ----------------------------------------------------
    @classmethod
    def from_data_file(cls, path: Path | None = None) -> ScopeEngine:
        path = path or _DATA_FILE
        raw = json.loads(path.read_text())
        buckets: dict[IpClass, list] = {IpClass.CDN: [], IpClass.CLOUD_SHARED: []}
        for provider in raw.get("providers", []):
            cls_name = provider.get("class", "cdn")
            ip_class = IpClass.CDN if cls_name == "cdn" else IpClass.CLOUD_SHARED
            buckets[ip_class].extend(_parse_networks(provider.get("cidrs", [])))
        return cls(buckets)

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
            if cls in HARD_DENY:
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

            # 5. Is this IP confirmed dedicated to the customer?
            is_dedicated = any(addr.version == n.version and addr in n for n in dedicated_nets)
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
    """Process-wide engine built from the bundled feed file."""
    return ScopeEngine.from_data_file()


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
