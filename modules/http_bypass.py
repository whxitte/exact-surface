"""403/401 access-control bypass detection (module: http_bypass).

An external attacker who hits a ``403 Forbidden`` doesn't stop there — they try the
well-known tricks that make a mis-configured proxy or app hand over the page anyway:
spoofed forwarding headers, URL-rewrite headers, and path-normalisation quirks. If any
of them works, the "protected" resource is effectively public. Finding that first, on
your own surface, is pure **detection** — the same request an attacker would send, with
no exploitation and nothing changed on the target.

This module is the pure, offline-testable engine: it builds the candidate request
matrix for a URL, decides which responses actually constitute a bypass, and (via an
injected ``probe``) runs them. The network probe (:func:`default_probe`) goes through
the SSRF-safe :mod:`modules.safe_http` guarded session with redirects **off**, so the
only host ever contacted is the in-scope endpoint itself — the spoofed values live only
in headers/paths, never in the TCP connection target.

Detection-only by construction:

* **Only safe HTTP methods** are used (GET/HEAD/OPTIONS and case-variants of GET).
  State-changing verbs (POST/PUT/PATCH/DELETE) are deliberately excluded — sending
  those to a real endpoint could modify data, which would cross from detection into
  action. Header and path techniques are where the real, safe signal is anyway.
* **Redirects are never followed** and the request host is never changed, so this can't
  be steered at internal infrastructure (no SSRF).
* We send benign probe requests, never exploit payloads.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

#: Baseline statuses that mean "the front door is shut" — the only case worth probing.
FORBIDDEN_STATUSES: frozenset[int] = frozenset({401, 403})
#: Unambiguous success — the resource was served where it was forbidden.
SUCCESS_STATUSES: frozenset[int] = frozenset({200, 201, 202, 203, 204, 206})
#: Redirects: weaker signal (could be to a login page), reported at lower confidence.
REDIRECT_STATUSES: frozenset[int] = frozenset({301, 302, 303, 307, 308})
#: Location substrings that mean a redirect went to auth, not to the resource.
_AUTH_REDIRECT_MARKERS: tuple[str, ...] = (
    "login",
    "signin",
    "sign-in",
    "auth",
    "sso",
    "logon",
    "account",
    "session",
)

#: Values that assert "this request is internal/local" for IP-forwarding headers.
#: These are HTTP *header values* sent to the target, never bind addresses (S104 N/A).
_LOCAL_VALUES: tuple[str, ...] = ("127.0.0.1", "localhost", "0.0.0.0", "::1")  # noqa: S104
#: Headers a mis-configured trust boundary may honour to believe the client is internal.
_IP_SPOOF_HEADERS: tuple[str, ...] = (
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "X-Forwarded-Server",
    "X-Forwarded",
    "Forwarded",
    "Forwarded-For",
    "X-Real-IP",
    "X-Client-IP",
    "X-Originating-IP",
    "X-Remote-IP",
    "X-Remote-Addr",
    "X-Host",
    "True-Client-IP",
    "Cluster-Client-IP",
    "Client-IP",
    "X-ProxyUser-Ip",
    "X-Custom-IP-Authorization",
)
#: The three most commonly-honoured spoof headers — try the full value set on these.
_EXTENDED_IP_HEADERS: tuple[str, ...] = ("X-Forwarded-For", "X-Real-IP", "X-Client-IP")
#: URL-rewrite headers: the front proxy blocks the path but the backend rewrites to it.
_URL_REWRITE_HEADERS: tuple[str, ...] = (
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Override-URL",
    "X-Http-Destinationurl",
)
#: Safe method-tampering set — see module docstring for why nothing state-changing.
_SAFE_METHODS: tuple[str, ...] = ("HEAD", "OPTIONS")
_METHOD_CASE_VARIANTS: tuple[str, ...] = ("get", "GeT")


@dataclass(frozen=True)
class ProbeResult:
    """What one request returned. ``body_sample`` is a bounded prefix used only to
    tell a real page apart from a WAF/block page served with a 200."""

    status: int
    length: int
    body_sample: str = ""
    location: str | None = None


@dataclass(frozen=True)
class Attempt:
    """One candidate request. ``url`` always keeps the original host — only the path
    and headers vary, so the connection target never changes."""

    technique: str  # "method" | "header" | "path"
    label: str  # human-readable, e.g. "X-Original-URL: /admin"
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)


Probe = Callable[[str, str, dict[str, str]], Awaitable[ProbeResult]]


# -- attempt matrix ----------------------------------------------------------
def _method_attempts(url: str) -> list[Attempt]:
    out = [
        Attempt("method", f"method {m}", m, url) for m in (*_SAFE_METHODS, *_METHOD_CASE_VARIANTS)
    ]
    return out


def _header_attempts(url: str) -> list[Attempt]:
    parts = urlsplit(url)
    path = parts.path or "/"
    root = urlunsplit((parts.scheme, parts.netloc, "/", "", ""))
    out: list[Attempt] = []

    # IP-forwarding spoof headers. Every header gets the classic 127.0.0.1; the most
    # commonly-honoured ones also get the wider value set.
    for header in _IP_SPOOF_HEADERS:
        values = _LOCAL_VALUES if header in _EXTENDED_IP_HEADERS else ("127.0.0.1",)
        for value in values:
            out.append(Attempt("header", f"{header}: {value}", "GET", url, {header: value}))

    # URL-rewrite headers: request the root, ask the backend to rewrite to the path.
    for header in _URL_REWRITE_HEADERS:
        out.append(Attempt("header", f"{header}: {path}", "GET", root, {header: path}))

    # Scheme/proto assertions.
    out += [
        Attempt("header", "X-Forwarded-Scheme: https", "GET", url, {"X-Forwarded-Scheme": "https"}),
        Attempt("header", "X-Forwarded-Proto: https", "GET", url, {"X-Forwarded-Proto": "https"}),
        Attempt("header", "X-Forwarded-Ssl: on", "GET", url, {"X-Forwarded-Ssl": "on"}),
    ]
    # Self-referer / AJAX-context headers some apps trust.
    out += [
        Attempt("header", f"Referer: {url}", "GET", url, {"Referer": url}),
        Attempt(
            "header",
            "X-Requested-With: XMLHttpRequest",
            "GET",
            url,
            {"X-Requested-With": "XMLHttpRequest"},
        ),
    ]
    return out


def _path_mutations(path: str) -> list[tuple[str, str]]:
    """(label, mutated_path) pairs — canonical proxy/normalisation-quirk tricks."""
    p = path or "/"
    stripped = p.rstrip("/") or "/"
    muts: list[tuple[str, str]] = []

    # Suffix tricks.
    _suffixes = (
        "/",
        "//",
        "/.",
        "/./",
        "/..;/",
        "%20",
        "%09",
        "%00",
        ".json",
        ".html",
        "~",
        "?",
        "#",
        ";",
    )
    for suffix in _suffixes:
        muts.append((f"suffix {suffix!r}", p + suffix))
    # Prefix tricks.
    for prefix in ("//", "/./", "/%2e/", "/.;/"):
        muts.append((f"prefix {prefix!r}", prefix.rstrip("/") + p if prefix != "//" else "/" + p))
    # Mid-path ..;/ before the last segment (Tomcat/Java path-param quirk).
    if "/" in stripped and stripped != "/":
        head, _, tail = stripped.rpartition("/")
        muts.append(("..;/ before last segment", f"{head}/..;/{tail}"))
        muts.append(("/./ before last segment", f"{head}/./{tail}"))
        # Case-toggle the last segment (case-sensitive ACL vs case-insensitive fs).
        if tail:
            muts.append(("case-toggled segment", f"{head}/{_swapcase(tail)}"))
            # URL-encode the first character of the last segment, and double-encode it.
            hexed = format(ord(tail[0]), "02x")
            muts.append(("url-encoded first char", f"{head}/%{hexed}{tail[1:]}"))
            muts.append(("double-encoded first char", f"{head}/%25{hexed}{tail[1:]}"))
    # Leading-dot / traversal-style within the same host.
    muts.append(("/. + path", "/." + p))
    muts.append(("%2e + path", "/%2e" + p))
    # De-dupe while preserving order.
    seen: set[str] = set()
    out: list[tuple[str, str]] = []
    for label, mp in muts:
        if mp not in seen and mp != p:
            seen.add(mp)
            out.append((label, mp))
    return out


def _swapcase(s: str) -> str:
    return s.swapcase()


def _path_attempts(url: str) -> list[Attempt]:
    parts = urlsplit(url)
    out: list[Attempt] = []
    for label, mpath in _path_mutations(parts.path or "/"):
        mutated = urlunsplit((parts.scheme, parts.netloc, mpath, parts.query, ""))
        out.append(Attempt("path", f"path: {label}", "GET", mutated))
    return out


def build_attempts(url: str) -> list[Attempt]:
    """The full candidate request matrix for *url* (methods + headers + paths)."""
    return _method_attempts(url) + _header_attempts(url) + _path_attempts(url)


# -- decision ----------------------------------------------------------------
def classify(baseline: ProbeResult, cand: ProbeResult) -> str | None:
    """Confidence that *cand* bypassed the *baseline* 403/401 — "high"/"medium"/None.

    A 2xx where we were forbidden is a bypass — unless the body is byte-identical to
    the forbidden response (a WAF/block page served with a 200). A non-auth redirect is
    a weaker (medium) signal. Anything else is not a bypass.
    """
    if baseline.status not in FORBIDDEN_STATUSES:
        return None
    if cand.status in SUCCESS_STATUSES:
        if cand.body_sample and cand.body_sample == baseline.body_sample:
            return None  # same page, just a different status code — not a real bypass
        return "high"
    if cand.status in REDIRECT_STATUSES:
        loc = (cand.location or "").lower()
        if any(marker in loc for marker in _AUTH_REDIRECT_MARKERS):
            return None
        return "medium"
    return None


def _curl(attempt: Attempt) -> str:
    parts = ["curl", "-sk"]
    if attempt.method != "GET":
        parts += ["-X", attempt.method]
    for k, v in attempt.headers.items():
        parts += ["-H", f"'{k}: {v}'"]
    parts.append(f"'{attempt.url}'")
    return " ".join(parts)


def _bypass_record(
    attempt: Attempt, cand: ProbeResult, confidence: str, baseline_status: int
) -> dict:
    return {
        "technique": attempt.technique,
        "label": attempt.label,
        "method": attempt.method,
        "url": attempt.url,
        "request_headers": dict(attempt.headers),
        "status": cand.status,
        "length": cand.length,
        "confidence": confidence,
        "evidence": (
            f"{attempt.method} {attempt.label} → {cand.status} "
            f"(baseline was {baseline_status}); {cand.length} bytes"
        ),
        "curl": _curl(attempt),
    }


# -- orchestration -----------------------------------------------------------
async def run_bypass(
    url: str,
    *,
    probe: Probe,
    reconfirm: bool = True,
    on_attempt: Callable[[Attempt], None] | None = None,
    on_hit: Callable[[dict], None] | None = None,
) -> dict:
    """Probe *url* for a 403/401 bypass. Pure orchestration around an injected *probe*.

    Establishes the live baseline first (state may have changed since discovery); if it
    isn't 401/403 there's nothing to bypass and we skip. Each candidate that looks like a
    bypass is re-confirmed with a second request (``reconfirm``) to shed load-balancer
    flap and one-off noise before it's recorded.
    """
    baseline = await probe(url, "GET", {})
    if baseline.status not in FORBIDDEN_STATUSES:
        return {
            "url": url,
            "skipped": True,
            "reason": f"baseline status {baseline.status} is not 401/403",
            "baseline_status": baseline.status,
            "attempts": 0,
            "bypasses": [],
        }

    attempts = build_attempts(url)
    found: list[dict] = []
    for attempt in attempts:
        if on_attempt is not None:
            on_attempt(attempt)
        try:
            cand = await probe(attempt.url, attempt.method, attempt.headers)
        except Exception:  # noqa: BLE001, S112 - a failed probe is simply not a bypass
            continue
        confidence = classify(baseline, cand)
        if confidence is None:
            continue
        if reconfirm:
            try:
                again = await probe(attempt.url, attempt.method, attempt.headers)
            except Exception:  # noqa: BLE001, S112
                continue
            if classify(baseline, again) is None:
                continue  # didn't reproduce — drop it
            cand = again
        record = _bypass_record(attempt, cand, confidence, baseline.status)
        found.append(record)
        if on_hit is not None:
            on_hit(record)

    # Strongest first, and cap what we persist so a pathological host can't bloat the doc.
    found.sort(key=lambda r: (r["confidence"] != "high", r["status"]))
    return {
        "url": url,
        "baseline_status": baseline.status,
        "attempts": len(attempts),
        "bypasses": found[:25],
    }


async def default_probe(  # pragma: no cover - real network
    url: str, method: str, headers: dict[str, str]
) -> ProbeResult:
    """Real network probe through the SSRF-safe guarded session (redirects off).

    The host is never changed and redirects are never followed, so the spoofed
    header/path values can only ever influence the *response*, never the connection
    target — no SSRF surface (§3.10)."""
    import aiohttp

    from modules.safe_http import assert_url_allowed, guarded_session

    assert_url_allowed(url)
    async with guarded_session() as session:
        async with session.request(
            method,
            url,
            headers=headers or None,
            timeout=aiohttp.ClientTimeout(total=10),
            ssl=False,
            allow_redirects=False,
        ) as resp:
            raw = await resp.content.read(200_000)
            return ProbeResult(
                status=resp.status,
                length=len(raw),
                body_sample=raw[:2000].decode("utf-8", errors="ignore"),
                location=resp.headers.get("Location"),
            )
