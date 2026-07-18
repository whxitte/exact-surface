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
        "site:{domain} ext:pem OR ext:key",
        "site:{domain} ext:dump OR ext:backup",
        'site:{domain} intitle:"index of"',
        'site:{domain} intitle:"index of" "parent directory"',
    ],
    "config": [
        "site:{domain} ext:conf",
        "site:{domain} ext:yml OR ext:yaml",
        "site:{domain} inurl:config",
        "site:{domain} ext:ini OR ext:cfg",
    ],
    "secrets": [
        'site:{domain} "api_key"',
        'site:{domain} "BEGIN RSA PRIVATE KEY" OR "BEGIN PRIVATE KEY"',
        'site:{domain} "aws_access_key_id"',
        'site:{domain} "api_secret" OR "client_secret"',
    ],
    # Indexed database connection strings — a full credential in one line (§9c-adjacent).
    "credentials": [
        'site:{domain} "DB_PASSWORD" OR "DATABASE_PASSWORD"',
        'site:{domain} "mongodb://" OR "postgresql://" OR "mysql://"',
        'site:{domain} "password=" OR "passwd=" OR "pwd="',
    ],
    # Indexed error pages / stack traces leak stack, framework, and internal paths.
    "error_pages": [
        'site:{domain} "sql syntax" OR "mysql_fetch" OR "ORA-"',
        'site:{domain} "Traceback (most recent call last)" OR "at java.lang"',
        'site:{domain} "Internal Server Error" OR "500 Internal"',
        'site:{domain} intitle:"phpinfo()"',
    ],
    # Indexed API surface — docs/schemas that map the whole API for an attacker.
    "api_exposure": [
        "site:{domain} inurl:swagger OR inurl:api-docs OR inurl:openapi",
        "site:{domain} inurl:graphql",
    ],
    "auth": [
        "site:{domain} inurl:admin",
        "site:{domain} inurl:login OR inurl:signin",
        'site:{domain} intitle:"dashboard"',
        "site:{domain} inurl:wp-admin OR inurl:phpmyadmin",
    ],
}

_CATEGORY_SEVERITY = {
    "credentials": Severity.CRITICAL,
    "secrets": Severity.CRITICAL,
    "exposed_files": Severity.HIGH,
    "error_pages": Severity.MEDIUM,
    "config": Severity.MEDIUM,
    "api_exposure": Severity.LOW,
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
