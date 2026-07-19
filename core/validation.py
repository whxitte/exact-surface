"""Server-side input validation for externally-supplied values (§8, §11).

Frontend checks are advisory — a request from curl/Burp bypasses them entirely — so
every user-controlled value is validated here, on the trust boundary, before it is
persisted or used. These helpers are pure and unit-tested; the API schemas
(:mod:`api.schemas`) call them from Pydantic validators so a bad value is a clean 422,
never a persisted or acted-on value.

The rule of thumb: reject rather than sanitize-and-guess. A value we don't understand
is refused with a clear message, not coerced into something that might scan or contact
the wrong thing.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from core.netguard import is_forbidden_target_ip, is_ip_literal

# A DNS label: 1–63 chars, alnum + hyphen, not starting/ending with a hyphen. A domain
# is two-or-more labels (an apex always has a dot), total length ≤253.
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_DOMAIN_RE = re.compile(rf"^(?:{_LABEL}\.)+{_LABEL}$")
#: chars that must never appear in a bare domain (scheme/path/port/userinfo/whitespace)
_DOMAIN_FORBIDDEN = set("/\\@:?#& \t\r\n%")

_TELEGRAM_TOKEN_RE = re.compile(r"^\d{5,20}:[A-Za-z0-9_-]{20,60}$")
_TELEGRAM_CHAT_RE = re.compile(r"^(-?\d{1,20}|@[A-Za-z][A-Za-z0-9_]{3,31})$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

MAX_EXCLUDED_HOSTS = 500
MAX_EXCLUDED_CIDRS = 500


def normalize_apex_domain(value: str) -> str:
    """Return the canonical bare domain, or raise ``ValueError``.

    Accepts ``Example.COM.`` → ``example.com``. Rejects anything that isn't a plain
    registrable domain: a URL, an IP, a path, a port, unicode/homograph tricks — all of
    which would otherwise flow into scope resolution and scanning.
    """
    v = value.strip().rstrip(".").lower()
    if not (3 <= len(v) <= 253):
        raise ValueError("domain must be 3–253 characters")
    if any(c in _DOMAIN_FORBIDDEN for c in v):
        raise ValueError("enter a bare domain like example.com (no scheme, path, or port)")
    # Reject a bare IP masquerading as a domain — programs are domains, not addresses.
    if is_ip_literal(v):
        raise ValueError("enter a domain name, not an IP address")
    if not _DOMAIN_RE.match(v):
        raise ValueError("not a valid domain name")
    return v


def normalize_hostname(value: str) -> str:
    """Validate a hostname for the exclusion list (same rules as a domain)."""
    v = value.strip().rstrip(".").lower()
    if not (1 <= len(v) <= 253):
        raise ValueError("hostname must be 1–253 characters")
    if any(c in _DOMAIN_FORBIDDEN for c in v) or not _DOMAIN_RE.match(v):
        raise ValueError(f"'{value}' is not a valid hostname")
    return v


def normalize_cidr(value: str) -> str:
    """Validate a CIDR/IP and return it normalised, or raise ``ValueError``."""
    try:
        return str(ipaddress.ip_network(value.strip(), strict=False))
    except ValueError as exc:
        raise ValueError(f"'{value}' is not a valid CIDR/IP") from exc


def validate_public_http_url(value: str) -> str:
    """Validate an outbound webhook URL: http(s) with a host, and not an obviously
    internal IP literal. This is the *input-time* check for immediate feedback — the
    authoritative, DNS-rebinding-safe control is the guarded session at delivery time
    (:mod:`modules.safe_http`), because a hostname can resolve to an internal address.
    """
    url = value.strip()
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise ValueError("URL must start with http:// or https://")
    host = parts.hostname
    if not host:
        raise ValueError("URL has no host")
    if len(url) > 2048:
        raise ValueError("URL is too long")
    if is_ip_literal(host) and is_forbidden_target_ip(host):
        raise ValueError("URL points at a non-public address")
    return url


def validate_telegram_token(value: str) -> str:
    """A Telegram bot token is ``<digits>:<hash>``. Rejecting anything else stops a
    token like ``x@169.254.169.254/`` from rewriting the request host (URL injection)."""
    v = value.strip()
    if not _TELEGRAM_TOKEN_RE.match(v):
        raise ValueError("invalid Telegram bot token")
    return v


def validate_telegram_chat_id(value: str) -> str:
    v = value.strip()
    if not _TELEGRAM_CHAT_RE.match(v):
        raise ValueError("invalid Telegram chat id")
    return v


def validate_email_address(value: str) -> str:
    v = value.strip()
    if len(v) > 254 or not _EMAIL_RE.match(v):
        raise ValueError("invalid email address")
    return v
