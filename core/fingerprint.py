"""Tech-stack hints + asset interest scoring (§4 core/fingerprint.py).

Two cheap, pure heuristics used across the pipeline:

* :func:`is_ephemeral_host` — flags preview/staging/dev environments, the exact
  leak surface agencies create and forget (the §module 19 differentiator).
* :func:`interest_score` — a 0–100 "look here first" score so scanning effort and
  alerting attention concentrate on the assets most likely to matter.
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

# Path/host hints that raise interest (admin surfaces, APIs, auth).
_HIGH_INTEREST = (
    "admin",
    "api",
    "auth",
    "login",
    "vpn",
    "git",
    "jenkins",
    "gitlab",
    "grafana",
    "kibana",
    "portal",
    "internal",
    "dashboard",
)


def is_ephemeral_host(host: str) -> bool:
    """True if the host looks like a preview/staging/dev environment."""
    h = host.lower().rstrip(".")
    if any(h.endswith(sfx) for sfx in _EPHEMERAL_HOST_SUFFIXES):
        return True
    return bool(_TOKEN_RE.search(h))


def interest_score(host: str, *, tech: list[str] | None = None, status: int | None = None) -> int:
    """Rough 0–100 attacker-interest score for prioritising scan/alert effort."""
    h = host.lower()
    score = 20
    if any(tok in h for tok in _HIGH_INTEREST):
        score += 35
    if is_ephemeral_host(h):
        score += 20  # forgotten envs are disproportionately exposed
    if tech:
        score += min(15, 5 * len(tech))
    if status is not None and status in (200, 401, 403):
        score += 10
    return max(0, min(100, score))
