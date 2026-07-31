"""Reverse-DNS sweep — hosts that exist in IP space but never appear in DNS.

Forward enumeration finds names somebody published. A PTR sweep of the ranges a company
actually owns finds the machines nobody published: the jump box, the old build server,
the appliance with a management interface. These are exactly the hosts a defender has
forgotten and an attacker has not.

**This module is the sharpest edge in the product**, because the input is a CIDR rather
than a name, and a CIDR is easy to get wrong in a way that scans somebody else's
network. So it only ever runs over ranges the §9b authorisation path has confirmed as
dedicated to this customer (asnmap-verified, never self-attested), and
:func:`expand` refuses anything larger than a /20 outright.

PTR lookups are ordinary DNS queries against public resolvers — nothing is sent to the
hosts themselves.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

#: Never expand a range larger than this. A /20 is 4096 addresses, which is already a
#: lot of DNS; anything bigger is almost certainly a misconfigured scope entry, and
#: expanding it would be the bug rather than the feature.
MAX_PREFIX_HOSTS = 4096
MIN_PREFIX_LEN = 20

#: Total addresses per run across all ranges.
MAX_TOTAL = 8192


@dataclass(frozen=True)
class ReverseHit:
    """A hostname discovered from an IP rather than the other way round."""

    ip: str
    hostname: str
    in_scope: bool  # does it belong to a domain we are authorised for?

    @property
    def is_new_surface(self) -> bool:
        """In-scope names found this way are the interesting ones: they are assets the
        customer owns that forward enumeration missed entirely."""
        return self.in_scope


def expand(cidr: str, *, limit: int = MAX_PREFIX_HOSTS) -> list[str]:
    """Addresses in *cidr*, or [] if it is too large or not a network.

    Refusing is the correct behaviour for an oversized range, not silently truncating:
    a /8 in a scope entry is a mistake, and quietly sweeping its first 4096 addresses
    would hide that mistake while still generating the traffic.
    """
    try:
        network = ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError:
        return []
    if network.version != 4:
        return []  # a v6 range is not enumerable, and pretending otherwise is a trap
    if network.prefixlen < MIN_PREFIX_LEN:
        return []
    hosts = [str(ip) for ip in network.hosts()] or [str(network.network_address)]
    return hosts[:limit]


def expand_all(cidrs: list[str], *, total: int = MAX_TOTAL) -> list[str]:
    """Addresses across several ranges, deduped and globally capped."""
    out: list[str] = []
    seen: set[str] = set()
    for cidr in cidrs:
        for ip in expand(cidr):
            if ip in seen:
                continue
            seen.add(ip)
            out.append(ip)
            if len(out) >= total:
                return out
    return out


def classify(ip: str, hostname: str, own_apexes: tuple[str, ...]) -> ReverseHit | None:
    """Turn a PTR answer into a hit, deciding whether the name is ours.

    A PTR that points at the hosting provider's own naming
    (``ec2-1-2-3-4.compute.amazonaws.com``) is not a discovery — it is the default, and
    reporting it would bury the handful of real names in thousands of rows.
    """
    hostname = (hostname or "").strip().rstrip(".").lower()
    if not hostname or hostname == ip:
        return None
    if _is_provider_default(hostname):
        return None
    in_scope = any(
        hostname == apex or hostname.endswith("." + apex) for apex in own_apexes if apex
    )
    return ReverseHit(ip=ip, hostname=hostname, in_scope=in_scope)


#: Reverse names cloud providers assign by default; they encode the IP, not an identity.
_PROVIDER_SUFFIXES = (
    "compute.amazonaws.com", "amazonaws.com", "cloudfront.net", "googleusercontent.com",
    "bc.googleusercontent.com", "1e100.net", "azure.com", "cloudapp.azure.com",
    "cloudapp.net", "digitalocean.com", "linodeusercontent.com", "vultrusercontent.com",
    "hetzner.de", "your-server.de", "ovh.net", "contaboserver.net", "oraclecloud.com",
    "telia.net", "comcast.net", "rr.com", "verizon.net", "level3.net",
)


def _is_provider_default(hostname: str) -> bool:
    return any(hostname.endswith(suffix) for suffix in _PROVIDER_SUFFIXES)
