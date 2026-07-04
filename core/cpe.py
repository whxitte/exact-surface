"""Tech-string → product/version parsing + version comparison for CVE matching.

Fingerprint→CPE→CVE is inherently noisy (§module 21). This module keeps the parsing
conservative and pure so the matcher (``modules/intelligence/cve_match.py``) can
attach an honest confidence to every match: a product match with a concrete,
in-range version is high confidence; a product match with no version is low.
"""

from __future__ import annotations

import re

_VERSION_SPLIT = re.compile(r"[\s:/@]+")
_VERSION_TOKEN = re.compile(r"^\d+(?:\.\d+)*$")

# Normalise common tech display names to a canonical product token.
_PRODUCT_ALIASES = {
    "wordpress": "wordpress",
    "wp": "wordpress",
    "nginx": "nginx",
    "apache": "apache",
    "apache httpd": "apache",
    "php": "php",
    "openssl": "openssl",
    "jquery": "jquery",
    "drupal": "drupal",
    "joomla": "joomla",
    "tomcat": "tomcat",
    "apache tomcat": "tomcat",
}


def normalize_product(name: str) -> str:
    key = name.strip().lower()
    return _PRODUCT_ALIASES.get(key, key)


def parse_tech(tech: str) -> tuple[str, str | None]:
    """Split a fingerprint tech string into ``(product, version|None)``.

    Handles ``"WordPress 5.4"``, ``"nginx:1.18.0"``, ``"PHP/7.4"`` and bare
    ``"nginx"``. The version is the last token that looks like a dotted number.
    """
    parts = [p for p in _VERSION_SPLIT.split(tech.strip()) if p]
    if not parts:
        return "", None
    version = None
    if _VERSION_TOKEN.match(parts[-1]):
        version = parts[-1]
        parts = parts[:-1]
    product = normalize_product(" ".join(parts)) if parts else ""
    return product, version


def parse_version(version: str) -> tuple[int, ...]:
    """Parse a dotted numeric version into a comparable tuple (non-numeric → ())."""
    if not version or not _VERSION_TOKEN.match(version):
        return ()
    return tuple(int(p) for p in version.split("."))


def _cmp(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    length = max(len(a), len(b))
    a = a + (0,) * (length - len(a))
    b = b + (0,) * (length - len(b))
    return (a > b) - (a < b)


def version_in_range(
    version: str,
    *,
    start_incl: str | None = None,
    end_excl: str | None = None,
    end_incl: str | None = None,
    exact: str | None = None,
) -> bool:
    """True if *version* falls within the given (any subset of) bounds."""
    v = parse_version(version)
    if not v:
        return False
    if exact is not None:
        return _cmp(v, parse_version(exact)) == 0
    if start_incl is not None and _cmp(v, parse_version(start_incl)) < 0:
        return False
    if end_excl is not None and _cmp(v, parse_version(end_excl)) >= 0:
        return False
    if end_incl is not None and _cmp(v, parse_version(end_incl)) > 0:
        return False
    return True


def to_cpe(product: str, version: str | None) -> str:
    """Build a loose CPE 2.3 string (vendor wildcarded)."""
    return f"cpe:2.3:a:*:{product or '*'}:{version or '*'}:*:*:*:*:*:*:*"
