"""Detected-tech → Nuclei template-tag selection (§7 module 7, engine quality).

ExactSurface's non-aggressive scan runs a fixed safe tag set on every host. That is safe
but blunt: a WordPress site and a Jenkins panel get the same generic templates. This
module maps the technologies httpx already fingerprinted to the Nuclei product tags
that actually matter for them, so the safe scan *adds* targeted coverage — a
WordPress host also gets WordPress templates — without widening the run to the full
9000-template library (slow, noisy on shared infra).

Two inputs, both cheap:

* **Detected tech** (Wappalyzer names from httpx) → product tags via ``TECH_TAG_MAP``.
* **The hostname itself** → inferred tech via ``DOMAIN_TECH_HINTS``. When a product
  sits behind a reverse proxy (``kibana.example.com`` fronted by nginx), httpx only
  sees the proxy — but the name gives it away. This is the single most common way an
  exposed admin panel hides from fingerprinting.

Everything here is pure data + string matching (no I/O), so it is exhaustively
unit-testable and lives in ``core``. It only ever *adds* tags to the safe baseline;
the harmful-tag exclusion (``dos,intrusive,fuzz``) is enforced independently in the
nuclei wrapper and is unaffected by anything here.
"""

from __future__ import annotations

from collections.abc import Iterable

#: Detected-technology keyword → Nuclei template tags to add. Keys are matched
#: case-insensitively as substrings against both the detected tech name and this
#: key (so "WordPress" matches "wordpress", and "wp" matches too). Values must be
#: real Nuclei tags — product names, which nuclei-templates tag their checks with.
TECH_TAG_MAP: dict[str, tuple[str, ...]] = {
    # CI/CD & DevOps — high value, frequently exposed/unauthenticated
    "jenkins": ("jenkins",),
    "gitlab": ("gitlab",),
    "grafana": ("grafana",),
    "kibana": ("kibana",),
    "elasticsearch": ("elasticsearch",),
    "sonarqube": ("sonarqube",),
    "airflow": ("airflow",),
    "jupyter": ("jupyter",),
    "vault": ("vault", "hashicorp"),
    "consul": ("consul", "hashicorp"),
    "argocd": ("argocd",),
    "kubernetes": ("kubernetes", "k8s"),
    "docker": ("docker",),
    # Database admin panels
    "phpmyadmin": ("phpmyadmin",),
    "pgadmin": ("pgadmin",),
    "adminer": ("adminer",),
    # CMS platforms
    "wordpress": ("wordpress", "wp-plugin"),
    "drupal": ("drupal",),
    "joomla": ("joomla",),
    "magento": ("magento",),
    "ghost": ("ghost",),
    # Application frameworks / servers
    "laravel": ("laravel",),
    "django": ("django",),
    "spring": ("spring", "springboot"),
    "struts": ("struts", "apache"),
    "tomcat": ("tomcat", "apache"),
    "weblogic": ("weblogic", "oracle"),
    "jboss": ("jboss",),
    "nginx": ("nginx",),
    "apache": ("apache",),
    "iis": ("iis", "microsoft"),
    "php": ("php",),
    # APIs & docs
    "graphql": ("graphql",),
    "swagger": ("swagger", "openapi"),
    # Monitoring & observability
    "prometheus": ("prometheus",),
    "netdata": ("netdata",),
    "zabbix": ("zabbix",),
    "splunk": ("splunk",),
    # Storage & messaging
    "minio": ("minio",),
    "rabbitmq": ("rabbitmq",),
    "jira": ("jira", "atlassian"),
    "confluence": ("confluence", "atlassian"),
}

#: Hostname substring → inferred technology. Used when a reverse proxy hides the
#: real product from httpx. The inferred tech is resolved through ``TECH_TAG_MAP``,
#: so it benefits from the same product-tag expansion.
DOMAIN_TECH_HINTS: dict[str, str] = {
    "kibana": "kibana",
    "grafana": "grafana",
    "elastic": "elasticsearch",
    "jenkins": "jenkins",
    "gitlab": "gitlab",
    "jira": "jira",
    "confluence": "confluence",
    "sonar": "sonarqube",
    "pgadmin": "pgadmin",
    "phpmyadmin": "phpmyadmin",
    "airflow": "airflow",
    "jupyter": "jupyter",
    "vault": "vault",
    "consul": "consul",
    "argo": "argocd",
    "prometheus": "prometheus",
    "minio": "minio",
    "rabbitmq": "rabbitmq",
    "grafana-": "grafana",
}


def _tags_for_tech(tech: str) -> set[str]:
    t = tech.lower()
    tags: set[str] = set()
    for key, mapped in TECH_TAG_MAP.items():
        # Substring match both ways: "wordpress 6.1" matches "wordpress", and a bare
        # "wp" hint matches too. Guard against trivially-short keys matching noise.
        if (key in t or t in key) and len(t) >= 2:
            tags.update(mapped)
    return tags


def nuclei_tags_for(technologies: Iterable[str] = (), hosts: Iterable[str] = ()) -> set[str]:
    """Nuclei product tags to add for the given detected tech + hostnames.

    The result is a *superset request*: tags to union onto the safe baseline, never
    a replacement. Returns an empty set when nothing matches, in which case the caller
    simply runs its baseline unchanged.
    """
    tags: set[str] = set()
    for tech in technologies:
        if tech:
            tags |= _tags_for_tech(tech)
    for host in hosts:
        if not host:
            continue
        h = host.lower()
        for hint, inferred in DOMAIN_TECH_HINTS.items():
            if hint in h:
                tags |= _tags_for_tech(inferred)
    return tags
