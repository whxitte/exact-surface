"""Search-dork templates by category (module 18-20).

Rendered against a domain to find *indexed* exposures — files and pages a search
engine already crawled that shouldn't be public. Category drives finding severity.
"""

from __future__ import annotations

from core.severity import Severity

DORK_TEMPLATES: dict[str, list[str]] = {
    "exposed_files": [
        "site:{domain} ext:env",
        "site:{domain} ext:sql",
        "site:{domain} ext:log",
        "site:{domain} ext:bak",
        'site:{domain} intitle:"index of"',
    ],
    "config": [
        "site:{domain} ext:conf",
        "site:{domain} ext:yml OR ext:yaml",
        "site:{domain} inurl:config",
    ],
    "secrets": [
        'site:{domain} "api_key"',
        'site:{domain} "BEGIN RSA PRIVATE KEY"',
        'site:{domain} "aws_access_key_id"',
    ],
    "auth": [
        "site:{domain} inurl:admin",
        "site:{domain} inurl:login",
        'site:{domain} intitle:"dashboard"',
    ],
}

_CATEGORY_SEVERITY = {
    "exposed_files": Severity.HIGH,
    "secrets": Severity.CRITICAL,
    "config": Severity.MEDIUM,
    "auth": Severity.LOW,
}


def category_severity(category: str) -> Severity:
    return _CATEGORY_SEVERITY.get(category, Severity.INFO)


def render(domain: str) -> list[dict]:
    """Return ``{category, query}`` dorks for *domain*."""
    return [
        {"category": category, "query": template.format(domain=domain)}
        for category, templates in DORK_TEMPLATES.items()
        for template in templates
    ]
