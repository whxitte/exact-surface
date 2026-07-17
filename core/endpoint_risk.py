"""Risk classification of discovered endpoints (§4/§7, signal quality).

Crawling surfaces hundreds of URLs; most are noise (static assets, tracking) and a
few are where an attacker actually looks — auth flows, admin panels, APIs, and
parameters prone to IDOR / SSRF / open-redirect. Vantari already scores *host*
interest (:mod:`core.fingerprint`); this classifies the *path and query* of a
specific endpoint, which is the granularity that separates ``/admin/users?id=42``
from ``/img/logo.png``.

The output is a set of category tags (``admin``, ``idor``, ``ssrf``, ``payment`` …)
stored on the :class:`~core.models.Endpoint`, so the UI can surface and filter the
handful of endpoints worth a human's attention. It is **classification only** — it
never triggers a scan or an alert by itself, so a loose rule costs a label, not a
request. Rules are data; tune :data:`INTEREST_RULES` without touching logic.

Pure (no I/O), so it is exhaustively unit-testable and lives in ``core``.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

# (compiled pattern against the lowercased path+query, category tag). Ordered by
# rough attacker value; a URL can match several and collects all their tags.
_RULES: tuple[tuple[re.Pattern[str], str], ...] = tuple(
    (re.compile(pat), tag)
    for pat, tag in (
        # -- authentication & access -------------------------------------------
        (r"/(?:login|signin|log-in|sign-in)\b", "auth"),
        (r"/(?:logout|register|signup|sign-up)\b", "auth"),
        (r"/(?:oauth|sso|saml|openid)\b", "auth"),
        (r"/(?:reset|forgot)[-_]?password\b", "auth"),
        (r"/(?:2fa|mfa|otp|verify)\b", "auth"),
        (r"(?:/|_)(?:token|jwt|refresh)\b", "token"),
        # -- admin & internal --------------------------------------------------
        (r"/(?:admin|administrator|superuser|staff)\b", "admin"),
        (r"/(?:dashboard|console|manage(?:ment)?|internal)\b", "admin"),
        (r"/(?:debug|actuator|_debug|phpinfo)\b", "debug"),
        # -- api ---------------------------------------------------------------
        (r"/(?:api|rest|rpc)\b", "api"),
        (r"/v[0-9]+/", "api"),
        (r"/graphql\b", "graphql"),
        (r"/(?:swagger|openapi|api-docs)\b", "api-docs"),
        (r"/(?:webhook|callback)\b", "webhook"),
        # -- data movement -----------------------------------------------------
        (r"/(?:upload|import)\b", "upload"),
        (r"/(?:export|download|backup)\b", "export"),
        # -- payment / sensitive business logic --------------------------------
        (r"/(?:payment|checkout|billing|invoice|refund|subscription)\b", "payment"),
        # -- config & secret exposure ------------------------------------------
        (r"/(?:\.env|\.git|\.svn|\.htaccess|wp-config|web\.config)\b", "exposure"),
        (r"\.(?:bak|old|sql|dump|log|zip|tar|tar\.gz|tgz|rar|7z)(?:$|\?)", "exposure"),
        (r"/(?:config|settings|credentials|secret)s?\b", "config"),
        # -- injectable parameters (the IDOR/SSRF/redirect surface) ------------
        (r"[?&](?:id|user_?id|uid|account|order_?id|product_?id|doc_?id)=", "idor"),
        (
            r"[?&](?:url|uri|dest|redirect|return|returnurl|next|continue|proxy|feed|target)=",
            "ssrf",
        ),
        (r"[?&](?:file|path|filename|template|document|folder|page)=", "lfi"),
    )
)

# Static-asset / third-party extensions that are never worth classifying.
_NOISE_EXT = re.compile(
    r"\.(?:png|jpe?g|gif|svg|ico|webp|woff2?|ttf|eot|css|map|mp[34]|avi|mov|pdf)(?:$|\?)"
)
_NOISE_HOST = ("google-analytics", "googletagmanager", "hotjar", "doubleclick", "gstatic")


def is_noise(url: str) -> bool:
    """True if a URL is a static asset or third-party junk — skip classification."""
    low = url.lower()
    if _NOISE_EXT.search(low):
        return True
    return any(h in low for h in _NOISE_HOST)


def classify_endpoint(url: str) -> list[str]:
    """Return the risk-category tags for *url* (sorted, deduped; empty for noise).

    Matches the path + query only, so the same route on http/https or across hosts
    classifies identically.
    """
    if is_noise(url):
        return []
    parts = urlsplit(url)
    target = (parts.path + ("?" + parts.query if parts.query else "")).lower()
    tags = {tag for pattern, tag in _RULES if pattern.search(target)}
    return sorted(tags)
