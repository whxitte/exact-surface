"""SSRF guard for in-process fetches to operator targets (§3.10 defensive).

ExactSurface fetches content from hosts it does not control — the takeover probe reads a
host's body, the secret scanner pulls JS/config URLs. Those targets are attacker-
influenced: a subdomain in scope can return ``302 → http://169.254.169.254/`` or a
DNS name that rebinds to an internal address between the scope check and the socket
connect. Following that would make ExactSurface fetch the cloud metadata endpoint and scan
the IAM credentials it returns as a "secret" — turning a scanned target into a thief
of *our* cloud role.

The scope engine gates *scanning* on the resolved IP, but that check happens on the
stored IP, once, before the fetch. This guard is the socket-level backstop: an IP
that is not globally routable — private, loopback, link-local (which includes the
169.254.169.254 metadata address), CGNAT, reserved, multicast, unspecified — must
never be connected to during an in-process fetch, no matter how we arrived at it.

Pure and stdlib-only (``ipaddress``), so it needs no feed and is always available.
"""

from __future__ import annotations

import ipaddress


def is_forbidden_target_ip(ip: str) -> bool:
    """True if *ip* must never be the target of an in-process fetch.

    Fails closed: an unparseable value is forbidden. The check is ``not is_global``
    (which already excludes private/loopback/link-local/CGNAT/reserved/…), with the
    individual flags repeated as defence-in-depth against any edge the stdlib treats
    as global that we still consider internal.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return (
        not addr.is_global
        or addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


def is_ip_literal(host: str) -> bool:
    """True if *host* is a bare IP address rather than a name to resolve."""
    try:
        ipaddress.ip_address(host.strip("[]"))  # strip IPv6 brackets
        return True
    except ValueError:
        return False
