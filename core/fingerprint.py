"""Tech-stack hints + asset interest triage (§4 core/fingerprint.py).

Two cheap, pure heuristics used across the pipeline:

* :func:`is_ephemeral_host` — flags preview/staging/dev environments, the exact
  leak surface agencies create and forget (the §module 19 differentiator).
* :func:`classify_interest` — triages a probed host into
  ``critical/high/medium/low/noise`` **with human-readable reasons**, so a
  researcher sees *why* a subdomain is worth looking at (an exposed Jenkins, an
  admin panel in the title, a 401 auth-bypass target). It reads the signals httpx
  already returns — tech, page title, status, server, hostname — and errs toward
  over-flagging at critical/high (a false positive there costs a glance; a false
  negative costs the finding). Idea adapted from the ZeroPoint reference engine's
  FingerprintClassifier; it replaces an earlier numeric ``interest_score`` that
  nothing ever consumed.
"""

from __future__ import annotations

import re

# Substrings / patterns that strongly indicate a non-production, often-forgotten env.
_EPHEMERAL_TOKENS = (
    "staging",
    "stage",
    "dev",
    "development",
    "uat",
    "qa",
    "test",
    "demo",
    "preview",
    "sandbox",
    "beta",
    "temp",
    "tmp",
    "internal",
    "old",
    "new",
)
_EPHEMERAL_HOST_SUFFIXES = (
    ".vercel.app",
    ".netlify.app",
    ".pages.dev",
    ".onrender.com",
    ".herokuapp.com",
    ".web.app",
    ".firebaseapp.com",
    ".ngrok.io",
    ".fly.dev",
    ".railway.app",
)
_TOKEN_RE = re.compile(r"(?:^|[.\-_])(" + "|".join(_EPHEMERAL_TOKENS) + r")(?:[.\-_0-9]|$)")


def is_ephemeral_host(host: str) -> bool:
    """True if the host looks like a preview/staging/dev environment."""
    h = host.lower().rstrip(".")
    if any(h.endswith(sfx) for sfx in _EPHEMERAL_HOST_SUFFIXES):
        return True
    return bool(_TOKEN_RE.search(h))


# -- interest triage ---------------------------------------------------------
#: Levels highest-first; index gives precedence when several rules match.
INTEREST_LEVELS = ("critical", "high", "medium", "low", "noise")
_RANK = {level: i for i, level in enumerate(reversed(INTEREST_LEVELS))}  # critical=4 … noise=0

#: (substring, reason, level) — matched against detected tech + server header.
_TECH_RULES: tuple[tuple[str, str, str], ...] = (
    ("jenkins", "Jenkins CI/CD exposed", "critical"),
    ("gitlab", "GitLab instance exposed", "critical"),
    ("jira", "Jira exposed", "critical"),
    ("confluence", "Confluence exposed", "critical"),
    ("grafana", "Grafana dashboard exposed", "critical"),
    ("kibana", "Kibana dashboard exposed", "critical"),
    ("elasticsearch", "Elasticsearch node exposed", "critical"),
    ("kubernetes", "Kubernetes component exposed", "critical"),
    ("airflow", "Apache Airflow exposed", "critical"),
    ("jupyter", "Jupyter notebook exposed", "critical"),
    ("vault", "HashiCorp Vault exposed", "critical"),
    ("consul", "HashiCorp Consul exposed", "critical"),
    ("pgadmin", "pgAdmin exposed", "critical"),
    ("phpmyadmin", "phpMyAdmin exposed", "critical"),
    ("adminer", "Adminer DB panel exposed", "critical"),
    ("sonarqube", "SonarQube exposed", "critical"),
    ("argo", "Argo CD/Workflows exposed", "critical"),
    ("wordpress", "WordPress CMS", "high"),
    ("drupal", "Drupal CMS", "high"),
    ("joomla", "Joomla CMS", "high"),
    ("magento", "Magento e-commerce", "high"),
    ("laravel", "Laravel framework", "high"),
    ("django", "Django framework", "high"),
    ("tomcat", "Apache Tomcat", "high"),
    ("weblogic", "Oracle WebLogic", "high"),
    ("jboss", "JBoss/WildFly", "high"),
    ("struts", "Apache Struts", "high"),
    ("spring", "Spring Boot", "high"),
    ("graphql", "GraphQL endpoint", "high"),
    ("swagger", "Swagger/OpenAPI docs exposed", "high"),
    ("prometheus", "Prometheus metrics exposed", "high"),
    ("minio", "MinIO object storage exposed", "high"),
    ("rabbitmq", "RabbitMQ management exposed", "high"),
)

#: (substring, reason, level) — matched against the page title.
_TITLE_RULES: tuple[tuple[str, str, str], ...] = (
    ("admin", "'admin' in title", "critical"),
    ("dashboard", "'dashboard' in title", "critical"),
    ("internal", "'internal' in title", "critical"),
    ("phpmyadmin", "phpMyAdmin in title", "critical"),
    ("login", "Login page", "high"),
    ("sign in", "Sign-in page", "high"),
    ("portal", "Portal in title", "high"),
    ("control panel", "Control panel in title", "high"),
    ("swagger", "Swagger UI", "high"),
    ("graphql", "GraphQL playground", "high"),
    ("index of", "Directory listing", "high"),
    ("upload", "File upload page", "high"),
    ("welcome to nginx", "nginx default page", "noise"),
    ("coming soon", "Coming-soon page", "noise"),
    ("parked", "Parked domain", "noise"),
    ("domain for sale", "Domain for sale", "noise"),
)

#: (hostname substring, reason, level) — matched against the hostname.
_HOST_RULES: tuple[tuple[str, str, str], ...] = (
    ("admin", "admin-* host", "critical"),
    ("jenkins", "jenkins-* host", "critical"),
    ("jira", "jira-* host", "critical"),
    ("kibana", "kibana-* host", "critical"),
    ("grafana", "grafana-* host", "critical"),
    ("gitlab", "gitlab-* host", "critical"),
    ("vault", "vault-* host", "critical"),
    ("internal", "internal-* host", "critical"),
    ("api", "API host", "high"),
    ("vpn", "VPN host", "high"),
    ("git", "git host", "high"),
    ("portal", "portal host", "high"),
    ("dashboard", "dashboard host", "high"),
    ("mail", "mail host", "medium"),
    ("smtp", "smtp host", "medium"),
    ("ftp", "ftp host", "medium"),
    ("cdn", "CDN host", "low"),
    ("static", "static-asset host", "low"),
    ("assets", "assets host", "low"),
)

#: status code → (reason, level). The 401/403 auth-boundary and 500 info-leak
#: signals the earlier score ignored.
_STATUS_RULES: dict[int, tuple[str, str]] = {
    401: ("HTTP 401 — auth-bypass target", "high"),
    403: ("HTTP 403 — potential bypass", "medium"),
    500: ("HTTP 500 — potential info leak", "medium"),
}


def classify_interest(
    hostname: str,
    *,
    tech: list[str] | None = None,
    title: str | None = None,
    status: int | None = None,
    server: str | None = None,
) -> tuple[str, list[str]]:
    """Triage a probed host into an interest level + the reasons for it.

    Pure: reads only the signals passed in. Returns ``(level, reasons)`` where
    ``level`` is one of :data:`INTEREST_LEVELS` and ``reasons`` explains it. The
    highest-ranked matching rule wins; every match contributes a reason.
    """
    level, reasons = "low", []
    blob = " ".join(tech or []).lower()
    if server:
        blob += " " + server.lower()
    h = hostname.lower()
    t = (title or "").lower()

    def _apply(matched_level: str, reason: str) -> None:
        nonlocal level
        reasons.append(reason)
        if _RANK[matched_level] > _RANK[level]:
            level = matched_level

    for sub, reason, lvl in _HOST_RULES:
        if re.search(rf"(?:^|[.\-]){re.escape(sub)}(?:[.\-]|$)", h) or f"{sub}." in h:
            _apply(lvl, reason)
    for sub, reason, lvl in _TECH_RULES:
        if sub in blob:
            _apply(lvl, reason)
    for sub, reason, lvl in _TITLE_RULES:
        if sub in t:
            _apply(lvl, reason)
    if status in _STATUS_RULES:
        reason, lvl = _STATUS_RULES[status]
        _apply(lvl, reason)
    if is_ephemeral_host(h):
        _apply("high", "forgotten env (staging/dev/preview)")

    return level, list(dict.fromkeys(reasons))  # dedupe, keep order
