"""Content-hash fingerprints — the idempotent upsert key for every entity.

State-awareness (§3.1) and idempotency (§3.2) both hinge on a *stable* fingerprint
per entity: identity-defining fields go into the hash, volatile fields (timestamps,
counters, response bodies) stay out. Re-observing the same fact produces the same
fingerprint, so the DB upsert is a no-op and ``is_new`` never re-fires.

Each entity's fingerprint inputs are defined here and nowhere else. Adding a new
entity type means adding its rule to this module.

Pure stdlib on purpose: these functions must never depend on I/O or third-party
libraries so they can be reasoned about and tested in isolation.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from urllib.parse import parse_qsl, urlsplit, urlunsplit

_DEFAULT_PORTS = {"http": 80, "https": 443}


def canonical_hash(*parts: object) -> str:
    """SHA-256 over a canonical JSON encoding of *parts*.

    Ordering is stabilised (``sort_keys=True``) and separators are fixed so the
    same logical value always serialises identically across processes.
    """
    payload = json.dumps(
        list(parts), sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def keyed_hash(value: str, key: bytes) -> str:
    """HMAC-SHA-256 of *value*. Used for secrets so the plaintext is never stored.

    The key is the app-tier secret-hash key (see ``core/config.py``); it must not
    live in the database, so a dumped DB cannot be brute-forced back to plaintext
    as cheaply as an unkeyed hash would allow.
    """
    return hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()


def normalize_url(url: str) -> str:
    """Canonicalise a URL for *endpoint identity*.

    Lower-cases scheme and host, drops default ports, removes fragments, keeps
    query-parameter *keys* but discards their *values* (``/s?q=a`` and ``/s?q=b``
    are the same endpoint), sorts the keys, and strips a trailing slash on
    non-root paths.
    """
    parts = urlsplit(url.strip())
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()

    netloc = host
    if parts.port and _DEFAULT_PORTS.get(scheme) != parts.port:
        netloc = f"{host}:{parts.port}"

    path = parts.path or "/"
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")

    keys = sorted({k.lower() for k, _ in parse_qsl(parts.query, keep_blank_values=True)})
    query = "&".join(keys)

    return urlunsplit((scheme, netloc, path, query, ""))


def asset_fingerprint(program_id: str, hostname: str) -> str:
    """Identity of a discovered host. Resolution changes are deltas, not new assets."""
    return canonical_hash("asset", program_id, hostname.lower().rstrip("."))


def endpoint_fingerprint(program_id: str, method: str, url: str) -> str:
    """Identity of an HTTP endpoint (method + normalised URL)."""
    return canonical_hash("endpoint", program_id, method.upper(), normalize_url(url))


def port_fingerprint(program_id: str, ip: str, port: int, protocol: str = "tcp") -> str:
    """Identity of an open port on an IP."""
    return canonical_hash("port", program_id, ip, int(port), protocol.lower())


def finding_fingerprint(
    program_id: str, check_id: str, location: str, locator: str = ""
) -> str:
    """Identity of a finding.

    Deliberately excludes the response body — bodies drift between scans while the
    finding is the same. ``check_id`` is the nuclei template id (or check name),
    ``location`` the matched URL/IP, ``locator`` an optional discriminator such as
    the parameter name or the key of an exposed secret.
    """
    return canonical_hash("finding", program_id, check_id, location, locator)


def secret_fingerprint(
    program_id: str, secret_value: str, source_locator: str, hmac_key: bytes
) -> str:
    """Identity of an exposed secret — keyed on a hash of the value, never plaintext."""
    value_hash = keyed_hash(secret_value, hmac_key)
    return canonical_hash("secret", program_id, value_hash, source_locator)


def cve_match_fingerprint(
    program_id: str, cve_id: str, asset_fp: str, cpe: str
) -> str:
    """Identity of a CVE-to-asset match."""
    return canonical_hash("cve_match", program_id, cve_id.upper(), asset_fp, cpe)
