"""Dependency-confusion exposure — internal package names nobody has claimed.

When a build references an internal package (``@acme/auth-client``) that does not exist
on the public registry, anyone can publish that name. Most package managers prefer the
public registry, or can be tricked into it, so the attacker's code runs inside the
customer's build — with their secrets and their deploy keys. This is how several very
large companies have been compromised, and the ingredients are usually sitting in
public JavaScript.

We already mine JS bundles, and bundlers leave package names in them. So this is pure
analysis of data we hold, plus one HEAD-equivalent lookup per candidate name against a
public registry. We never publish, claim or reserve anything — that would be the
attack, not the detection of it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from core.severity import Severity

#: npm scoped (@scope/name) and bare package names as they appear in bundled output —
#: webpack/rollup keep them in module maps, sourceMappingURL comments and require paths.
_SCOPED = re.compile(r"[\"'`/](@[a-z0-9][\w.-]{0,63}/[a-z0-9][\w.-]{0,127})[\"'`/]", re.I)
_NODE_MODULES = re.compile(r"node_modules/((?:@[\w.-]+/)?[a-z0-9][\w.-]*)", re.I)

#: Names that are certainly public or are framework noise, not internal packages.
_IGNORE = frozenset(
    {
        "react",
        "react-dom",
        "next",
        "vue",
        "angular",
        "lodash",
        "axios",
        "moment",
        "jquery",
        "core-js",
        "rxjs",
        "tslib",
        "webpack",
        "babel",
        "regenerator-runtime",
        "scheduler",
        "prop-types",
        "classnames",
        "date-fns",
        "uuid",
        "zod",
        "swr",
    }
)

#: Scopes owned by well-known vendors — a miss there is a typo, not an exposure.
_PUBLIC_SCOPES = frozenset(
    {
        "@babel",
        "@types",
        "@next",
        "@vue",
        "@angular",
        "@emotion",
        "@mui",
        "@reduxjs",
        "@tanstack",
        "@sentry",
        "@stripe",
        "@aws-sdk",
        "@azure",
        "@google-cloud",
        "@testing-library",
        "@floating-ui",
        "@radix-ui",
        "@headlessui",
        "@vercel",
    }
)

MAX_CANDIDATES = 150


@dataclass(frozen=True)
class PackageRef:
    """A package name found in the customer's own published JavaScript."""

    name: str
    found_in: str
    scoped: bool

    @property
    def scope(self) -> str:
        return self.name.split("/", 1)[0] if self.name.startswith("@") else ""


@dataclass(frozen=True)
class ConfusionRisk:
    package: PackageRef
    registry: str = "npm"

    @property
    def severity(self) -> Severity:
        # A scoped name is strong evidence of a private package: scopes are how
        # organisations namespace internal code. An unscoped miss is more often a
        # renamed or removed dependency, so it is reported lower.
        return Severity.HIGH if self.package.scoped else Severity.MEDIUM

    @property
    def evidence(self) -> str:
        return (
            f"The package '{self.package.name}' is referenced in your published "
            f"JavaScript ({self.package.found_in}) but is not registered on {self.registry}. "
            "Anyone can publish that exact name. Depending on how your build resolves "
            "packages, their code could then be installed and executed inside your CI "
            "with access to whatever that build can reach."
        )

    @property
    def remediation(self) -> str:
        return (
            f"Register '{self.package.name}' on the public {self.registry} registry as a "
            "placeholder even though you host it privately — that permanently denies the "
            "name to an attacker. Also pin your installer to your internal registry for "
            "this scope so a public package can never take priority."
        )


def extract_packages(
    js_body: str, source_url: str, *, limit: int = MAX_CANDIDATES
) -> list[PackageRef]:
    """Package names referenced by a bundle, filtered down to plausible internal ones."""
    seen: dict[str, PackageRef] = {}

    for match in _SCOPED.findall(js_body or ""):
        name = match.lower()
        if name.split("/", 1)[0] in _PUBLIC_SCOPES or name in seen:
            continue
        seen[name] = PackageRef(name=name, found_in=source_url, scoped=True)

    for match in _NODE_MODULES.findall(js_body or ""):
        name = match.lower().rstrip("/")
        if name in seen or name in _IGNORE:
            continue
        if name.startswith("@") and name.split("/", 1)[0] in _PUBLIC_SCOPES:
            continue
        seen[name] = PackageRef(name=name, found_in=source_url, scoped=name.startswith("@"))
        if len(seen) >= limit:
            break

    return list(seen.values())[:limit]


def registry_url(name: str) -> str:
    """The public npm metadata URL for *name*. 404 there means the name is free."""
    return f"https://registry.npmjs.org/{name.replace('/', '%2F')}"


def assess(package: PackageRef, status: int) -> ConfusionRisk | None:
    """A 404 from the registry means nobody owns the name. Anything else means it
    exists (or the registry is unhappy), and we stay quiet rather than guess."""
    return ConfusionRisk(package=package) if status == 404 else None
