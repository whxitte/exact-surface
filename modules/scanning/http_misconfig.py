"""CORS, open-redirect and WAF analysis — pure functions over HTTP responses.

Three classic classes a hunter checks on every host, all of which are decided by
*reading a response*, never by exploiting one:

* **CORS** — a server that reflects an arbitrary ``Origin`` back in
  ``Access-Control-Allow-Origin`` *while* allowing credentials lets any website read
  authenticated responses on behalf of a logged-in victim. We send one extra request
  with a probe origin and read two headers. Nothing is exfiltrated.
* **Open redirect** — a redirect parameter that sends the browser to an arbitrary
  external host. We follow nothing: we read the ``Location`` header of a single
  non-following request and check where it *would* have gone. The probe host is a
  reserved example domain, so even a request that escapes lands nowhere real.
* **WAF** — not a finding, context. Knowing a host sits behind Cloudflare explains why
  it returned less than its neighbour, and knowing which hosts are *not* behind one
  tells the operator where their unprotected surface actually is.

Everything here takes response data and returns verdicts, so the rules are tested
directly against crafted headers with no network involved.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

from core.severity import Severity

#: Origin we ask the server to reflect. RFC 2606 reserves example.com, so this can
#: never be a host somebody else controls.
PROBE_ORIGIN = "https://exactsurface-cors-probe.example.com"

#: Where an open redirect would send a victim. Also reserved, for the same reason.
PROBE_REDIRECT_HOST = "exactsurface-redirect-probe.example.com"
PROBE_REDIRECT_URL = f"https://{PROBE_REDIRECT_HOST}/"

#: Query parameters that conventionally carry a post-action destination.
REDIRECT_PARAMS: tuple[str, ...] = (
    "url",
    "redirect",
    "redirect_uri",
    "redirect_url",
    "next",
    "return",
    "returnUrl",
    "return_url",
    "returnTo",
    "return_to",
    "goto",
    "dest",
    "destination",
    "continue",
    "target",
    "rurl",
    "forward",
    "callback",
    "back",
    "backurl",
    "r",
    "u",
)

#: header -> product. Matched case-insensitively against header NAMES.
_WAF_HEADERS: dict[str, str] = {
    "cf-ray": "Cloudflare",
    "cf-cache-status": "Cloudflare",
    "x-akamai-transformed": "Akamai",
    "x-sucuri-id": "Sucuri",
    "x-sucuri-cache": "Sucuri",
    "x-amz-cf-id": "AWS CloudFront",
    "x-amzn-waf-action": "AWS WAF",
    "x-iinfo": "Imperva Incapsula",
    "x-cdn": "Generic CDN",
    "x-azure-ref": "Azure Front Door",
    "x-fastly-request-id": "Fastly",
}

#: (header, substring) -> product, for values rather than names.
_WAF_VALUES: tuple[tuple[str, str, str], ...] = (
    ("server", "cloudflare", "Cloudflare"),
    ("server", "awselb", "AWS ELB"),
    ("server", "akamaighost", "Akamai"),
    ("server", "sucuri", "Sucuri"),
    ("server", "barracuda", "Barracuda"),
    ("server", "big-ip", "F5 BIG-IP"),
    ("set-cookie", "__cfduid", "Cloudflare"),
    ("set-cookie", "incap_ses", "Imperva Incapsula"),
    ("set-cookie", "visid_incap", "Imperva Incapsula"),
    ("set-cookie", "ts01", "F5 BIG-IP"),
    ("set-cookie", "barra_counter", "Barracuda"),
    ("powered-by-chartio", "", ""),  # placeholder never matches; keeps tuple shape honest
)


def _lower_headers(headers: dict) -> dict[str, str]:
    return {str(k).lower(): str(v) for k, v in (headers or {}).items()}


# --------------------------------------------------------------------------
# CORS
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class CorsVerdict:
    url: str
    allow_origin: str
    allow_credentials: bool
    kind: str  # reflected-origin | null-origin | wildcard-with-credentials | ""
    severity: Severity
    evidence: str

    @property
    def vulnerable(self) -> bool:
        return bool(self.kind)


def analyse_cors(url: str, headers: dict, *, probe_origin: str = PROBE_ORIGIN) -> CorsVerdict:
    """Decide whether a response's CORS headers hand data to an arbitrary origin.

    The dangerous combination is *permissive origin* + ``Allow-Credentials: true``.
    A wildcard alone is normal for public APIs and browsers refuse to send credentials
    with it, so reporting that as a vulnerability is noise — we say so explicitly
    rather than staying silent, because "we checked and it's fine" is information too.
    """
    h = _lower_headers(headers)
    allow = h.get("access-control-allow-origin", "").strip()
    creds = h.get("access-control-allow-credentials", "").strip().lower() == "true"

    kind, severity, evidence = "", Severity.INFO, ""
    if allow == probe_origin and creds:
        kind = "reflected-origin"
        severity = Severity.HIGH
        evidence = (
            f"The server echoed our arbitrary Origin ({probe_origin}) back in "
            "Access-Control-Allow-Origin and set Access-Control-Allow-Credentials: true. "
            "Any website a logged-in user visits can therefore read authenticated "
            "responses from this host."
        )
    elif allow == probe_origin:
        kind = "reflected-origin"
        severity = Severity.LOW
        evidence = (
            f"The server echoed our arbitrary Origin ({probe_origin}) back in "
            "Access-Control-Allow-Origin. Credentials are not allowed, so this does not "
            "expose authenticated data, but the reflection means the allow-list is not "
            "actually restricting anything."
        )
    elif allow == "null" and creds:
        kind = "null-origin"
        severity = Severity.HIGH
        evidence = (
            "Access-Control-Allow-Origin is 'null' with credentials allowed. A sandboxed "
            "iframe or a data: URL sends Origin: null, so an attacker can reach this "
            "endpoint with the victim's cookies."
        )
    elif allow == "*" and creds:
        # Browsers reject this pairing, but it signals a misconfigured allow-list and a
        # non-browser client will happily use it.
        kind = "wildcard-with-credentials"
        severity = Severity.MEDIUM
        evidence = (
            "Access-Control-Allow-Origin is '*' together with "
            "Access-Control-Allow-Credentials: true. Browsers refuse this combination, "
            "so it usually means the allow-list logic is broken rather than absent."
        )

    return CorsVerdict(url, allow, creds, kind, severity, evidence)


# --------------------------------------------------------------------------
# Open redirect
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class RedirectVerdict:
    url: str  # the URL we probed (with the payload in place)
    param: str
    location: str
    severity: Severity
    evidence: str

    @property
    def vulnerable(self) -> bool:
        return bool(self.location)


def redirect_candidates(url: str, *, payload: str = PROBE_REDIRECT_URL) -> list[tuple[str, str]]:
    """``(param, probe_url)`` for each redirect-looking parameter already on *url*.

    We only rewrite parameters the target itself published. Inventing parameter names
    would be fuzzing — more requests, more noise, and outside what a detection-only
    product should do unannounced.
    """
    parts = urlsplit(url)
    if not parts.query:
        return []
    params = parse_qs(parts.query, keep_blank_values=True)
    out: list[tuple[str, str]] = []
    for name in params:
        if name.lower() not in {p.lower() for p in REDIRECT_PARAMS}:
            continue
        probed = {k: list(v) for k, v in params.items()}
        probed[name] = [payload]
        out.append((name, urlunsplit(parts._replace(query=urlencode(probed, doseq=True)))))
    return out


def analyse_redirect(
    url: str,
    param: str,
    status: int,
    headers: dict,
    *,
    probe_host: str = PROBE_REDIRECT_HOST,
) -> RedirectVerdict:
    """True when the response tries to send the browser to our probe host."""
    if not 300 <= status < 400:
        return RedirectVerdict(url, param, "", Severity.INFO, "")
    location = _lower_headers(headers).get("location", "").strip()
    if not location:
        return RedirectVerdict(url, param, "", Severity.INFO, "")

    host = (urlsplit(location).hostname or "").lower()
    # Protocol-relative (//evil.com) has no scheme but still leaves the site.
    if not host and location.startswith("//"):
        host = location[2:].split("/", 1)[0].lower()
    if host != probe_host:
        return RedirectVerdict(url, param, "", Severity.INFO, "")

    return RedirectVerdict(
        url,
        param,
        location,
        Severity.MEDIUM,
        (
            f"Setting ?{param}= to an external URL made the server respond {status} with "
            f"Location: {location}. Anyone can send a link that starts on this trusted "
            "domain and lands the victim somewhere else — the standard opening move for "
            "phishing, and a way to steal OAuth tokens when this host is a redirect_uri."
        ),
    )


# --------------------------------------------------------------------------
# WAF / CDN fingerprint
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class WafVerdict:
    url: str
    products: tuple[str, ...] = field(default=())

    @property
    def protected(self) -> bool:
        return bool(self.products)


def fingerprint_waf(url: str, headers: dict) -> WafVerdict:
    """Which WAF/CDN, if any, fronts this host — inferred from response headers only."""
    h = _lower_headers(headers)
    found: list[str] = []
    for name, product in _WAF_HEADERS.items():
        if name in h and product not in found:
            found.append(product)
    for header, needle, product in _WAF_VALUES:
        if not needle or not product:
            continue
        if needle in h.get(header, "").lower() and product not in found:
            found.append(product)
    return WafVerdict(url, tuple(found))
