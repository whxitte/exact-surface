"""API surface discovery — robots/sitemap mining, API schemas, GraphQL, `.well-known`.

Four things a target publishes about itself, all readable with plain GET requests:

* **robots.txt** — administrators routinely *list* the paths they want kept out of
  search results. Every ``Disallow:`` is a path someone thought was worth hiding.
* **sitemap.xml** — the site's own inventory of URLs, often including pages no link
  points at any more.
* **API schemas** — an exposed ``swagger.json`` / ``openapi.yaml`` hands over every
  route, parameter and auth requirement in one file. That is the whole API.
* **GraphQL introspection** — the same thing for GraphQL: one POST returns the
  complete type system, including mutations that were never meant to be public.

The GraphQL check sends the standard introspection query and reads the reply. It asks
the server to describe itself; it never invokes a mutation or reads user data.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from core.severity import Severity

#: Conventional locations for an API schema. Ordered by how often they're real.
SCHEMA_PATHS: tuple[str, ...] = (
    "/swagger.json", "/swagger/v1/swagger.json", "/openapi.json", "/openapi.yaml",
    "/api/swagger.json", "/api/openapi.json", "/api-docs", "/api/api-docs",
    "/v1/openapi.json", "/v2/api-docs", "/v3/api-docs", "/swagger-ui.html",
    "/docs/openapi.json", "/redoc", "/swagger/index.html",
)

#: Conventional GraphQL endpoints.
GRAPHQL_PATHS: tuple[str, ...] = (
    "/graphql", "/api/graphql", "/v1/graphql", "/query", "/graphiql", "/gql",
)

#: `.well-known` resources worth knowing about. security.txt is a *good* sign; the
#: others can leak more than intended.
WELL_KNOWN_PATHS: tuple[str, ...] = (
    "/.well-known/security.txt",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/.well-known/assetlinks.json",
    "/.well-known/apple-app-site-association",
    "/.well-known/change-password",
)

#: The minimal introspection query. Depth 1 — enough to prove introspection is open
#: and to name the types, without pulling a megabyte of schema.
INTROSPECTION_QUERY = (
    "{__schema{queryType{name} mutationType{name} "
    "types{name kind description}}}"
)

_SITEMAP_LOC = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.I)
_ROBOTS_RULE = re.compile(r"^\s*(disallow|allow|sitemap)\s*:\s*(\S.*?)\s*$", re.I | re.M)

#: Paths whose appearance in robots.txt is itself interesting — an admin telling
#: search engines to stay away from the thing an attacker most wants.
_JUICY = (
    "admin", "internal", "private", "backup", "config", "secret", "staging", "dev",
    "test", "api", "console", "manage", "portal", "dashboard", "phpmyadmin", "wp-admin",
    ".git", ".env", "debug", "logs", "db", "sql", "upload",
)


@dataclass(frozen=True)
class DiscoveredPath:
    """A path the target told us about, and where it came from."""

    path: str
    source: str  # robots | sitemap
    interesting: bool = False


@dataclass(frozen=True)
class ApiSchema:
    url: str
    kind: str  # openapi | graphql | well-known
    detail: str = ""
    severity: Severity = Severity.INFO
    endpoints: tuple[str, ...] = field(default=())


def parse_robots(body: str, base_url: str) -> tuple[list[DiscoveredPath], list[str]]:
    """``(paths, sitemap_urls)`` from a robots.txt body.

    Wildcards are kept as-is rather than expanded: ``/admin/*`` tells us ``/admin/``
    exists, which is the signal; guessing what the ``*`` stands for would be fuzzing.
    """
    paths: list[DiscoveredPath] = []
    sitemaps: list[str] = []
    seen: set[str] = set()
    for directive, value in _ROBOTS_RULE.findall(body or ""):
        directive = directive.lower()
        if directive == "sitemap":
            if value.startswith("http"):
                sitemaps.append(value)
            continue
        if value in {"/", "*", ""} or value in seen:
            continue
        seen.add(value)
        clean = value.split("#", 1)[0].strip()
        if not clean.startswith("/"):
            continue
        lowered = clean.lower()
        paths.append(
            DiscoveredPath(
                path=urljoin(base_url, clean.replace("*", "")),
                source="robots",
                interesting=any(j in lowered for j in _JUICY),
            )
        )
    return paths, sitemaps


def parse_sitemap(body: str, *, limit: int = 2000) -> list[DiscoveredPath]:
    """URLs from a sitemap.xml (or sitemap index). Bounded — some sitemaps are huge."""
    out: list[DiscoveredPath] = []
    seen: set[str] = set()
    for loc in _SITEMAP_LOC.findall(body or ""):
        if loc in seen or not loc.startswith("http"):
            continue
        seen.add(loc)
        lowered = loc.lower()
        out.append(
            DiscoveredPath(
                path=loc,
                source="sitemap",
                interesting=any(j in lowered for j in _JUICY),
            )
        )
        if len(out) >= limit:
            break
    return out


def is_sitemap_index(body: str) -> bool:
    return "<sitemapindex" in (body or "").lower()


def analyse_schema(
    url: str, status: int, body: str, content_type: str = ""
) -> ApiSchema | None:
    """Recognise an OpenAPI/Swagger document and pull its route list out.

    A 200 that happens to be the site's HTML error page is the common false positive,
    so we require the document to actually parse as a schema rather than trusting the
    status code.
    """
    if status != 200 or not body:
        return None
    head = body[:4000].lower()
    is_json = "json" in content_type.lower() or body.lstrip().startswith("{")

    if is_json:
        try:
            doc = json.loads(body)
        except (ValueError, TypeError):
            return None
        if not isinstance(doc, dict):
            return None
        if not ({"swagger", "openapi"} & set(doc)):
            return None
        paths = doc.get("paths")
        routes = tuple(sorted(paths)[:200]) if isinstance(paths, dict) else ()
        title = ""
        info = doc.get("info")
        if isinstance(info, dict):
            title = str(info.get("title") or "")
        return ApiSchema(
            url=url,
            kind="openapi",
            detail=(
                "A machine-readable API schema is publicly served"
                + (f" ({title})" if title else "")
                + ". "
                f"It documents {len(routes)} route(s), with their parameters and auth "
                "requirements — everything needed to call the API, without a single guess."
            ),
            severity=Severity.MEDIUM if routes else Severity.LOW,
            endpoints=routes,
        )

    # YAML or a rendered docs page: detect, but don't pretend to parse routes.
    if any(k in head for k in ("swagger:", "openapi:", "swagger-ui", "redoc")):
        return ApiSchema(
            url=url,
            kind="openapi",
            detail=(
                "An API documentation page or YAML schema is publicly reachable. It "
                "describes the API's routes and parameters to anyone who asks."
            ),
            severity=Severity.LOW,
        )
    return None


def analyse_graphql(url: str, status: int, body: str) -> ApiSchema | None:
    """Detect a GraphQL endpoint with introspection left enabled."""
    if status not in (200, 400) or not body:
        return None
    try:
        doc = json.loads(body)
    except (ValueError, TypeError):
        return None
    if not isinstance(doc, dict):
        return None

    schema = (doc.get("data") or {}).get("__schema") if isinstance(doc.get("data"), dict) else None
    if isinstance(schema, dict):
        types = schema.get("types") or []
        names = tuple(
            str(t.get("name"))
            for t in types
            if isinstance(t, dict) and not str(t.get("name", "")).startswith("__")
        )[:200]
        mutation_type = schema.get("mutationType") or {}
        mutation = mutation_type.get("name") if mutation_type else None
        return ApiSchema(
            url=url,
            kind="graphql",
            detail=(
                "GraphQL introspection is enabled. One unauthenticated query returns the "
                f"complete schema — {len(names)} type(s)"
                + (f" and the '{mutation}' mutation root" if mutation else "")
                + ". An attacker gets the full API contract, including operations that were "
                "never linked anywhere."
            ),
            severity=Severity.MEDIUM,
            endpoints=names,
        )

    # A GraphQL server that refuses introspection still identifies itself by erroring
    # in GraphQL's own error shape. Worth recording as surface, not as a finding.
    if "errors" in doc and isinstance(doc.get("errors"), list):
        return ApiSchema(
            url=url,
            kind="graphql",
            detail=(
                "A GraphQL endpoint is present but introspection appears disabled — the "
                "server answered with a GraphQL error rather than a schema. Recorded as "
                "attack surface; this is the correct configuration."
            ),
            severity=Severity.INFO,
        )
    return None


def well_known_severity(path: str, status: int, body: str) -> tuple[Severity, str] | None:
    """Classify a `.well-known` hit. security.txt present is *good news*, and saying so
    is part of showing the work rather than only ever reporting problems."""
    if status != 200:
        return None
    name = urlsplit(path).path.rsplit("/", 1)[-1]
    if name == "security.txt":
        return Severity.INFO, (
            "A security.txt is published — researchers have a documented way to report "
            "issues. This is good practice and is recorded for completeness."
        )
    if name in ("openid-configuration", "oauth-authorization-server"):
        return Severity.INFO, (
            "An OAuth/OIDC discovery document is public (as the spec intends). It names "
            "the authorisation, token and JWKS endpoints, which is where an attacker "
            "starts when probing your identity layer."
        )
    return Severity.INFO, f"{name} is publicly served."
