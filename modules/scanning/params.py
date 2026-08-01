"""Parameter discovery — the query parameters an app accepts but never advertises.

Hidden parameters are where injection, IDOR and debug-mode bugs live. A page you can
list is not the same as attack surface you can describe: `/report` is one thing,
`/report?debug=1&user_id=` is another.

Two halves, deliberately separated because their cost is completely different:

1. **The observed inventory** — every parameter already visible in crawled URLs, mined
   JS and archived history. This costs *nothing*: it is a read over data we hold, and
   it is usually the majority of the real surface. It runs always.
2. **The candidate probe** — a small curated list of parameters that change behaviour
   when they exist (`debug`, `admin`, `test`, `redirect`). This costs one request per
   batch, so it is bounded and opt-in.

The probe decides by *comparison*, never by exploitation: fetch a baseline, fetch again
with the parameter, and report only if the response meaningfully changed. A parameter
that alters behaviour is a fact about the app; what it does with a hostile value is a
question this product does not ask.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

from core.severity import Severity

#: High-signal parameters worth probing for. Chosen because their mere existence is
#: interesting — not a generic wordlist, which would be fuzzing with extra steps.
CANDIDATE_PARAMS: tuple[str, ...] = (
    "debug",
    "test",
    "admin",
    "is_admin",
    "isAdmin",
    "role",
    "trace",
    "verbose",
    "dev",
    "development",
    "staging",
    "preview",
    "draft",
    "internal",
    "show_errors",
    "showerrors",
    "display_errors",
    "error",
    "errors",
    "source",
    "src",
    "raw",
    "format",
    "output",
    "callback",
    "jsonp",
    "id",
    "user_id",
    "userid",
    "uid",
    "account",
    "account_id",
    "customer_id",
    "file",
    "path",
    "template",
    "page",
    "view",
    "include",
    "doc",
    "cmd",
    "exec",
    "query",
    "q",
    "search",
    "filter",
    "sort",
    "order",
    "token",
    "key",
    "api_key",
    "apikey",
    "access_token",
    "auth",
    "next",
    "url",
    "redirect",
    "return",
    "continue",
)

#: Parameters whose presence is itself worth a finding, not just an inventory row.
_NOTABLE: dict[str, tuple[Severity, str]] = {
    "debug": (Severity.MEDIUM, "a debug switch"),
    "trace": (Severity.MEDIUM, "a trace switch"),
    "verbose": (Severity.LOW, "a verbosity switch"),
    "show_errors": (Severity.MEDIUM, "an error-display switch"),
    "display_errors": (Severity.MEDIUM, "an error-display switch"),
    "is_admin": (Severity.HIGH, "an admin flag"),
    "isadmin": (Severity.HIGH, "an admin flag"),
    "admin": (Severity.HIGH, "an admin flag"),
    "role": (Severity.HIGH, "a role selector"),
    "internal": (Severity.MEDIUM, "an internal-mode switch"),
    "source": (Severity.MEDIUM, "a source-view switch"),
    "raw": (Severity.LOW, "a raw-output switch"),
}

#: A probe value that is inert everywhere: not a number, not a path, not a script.
PROBE_VALUE = "exactsurface"

#: How much a response must change before we believe the parameter did something.
#: Pages carry per-request noise (timestamps, CSRF tokens, ad slots), so a couple of
#: bytes is not a signal. 64 is comfortably above that and well below a real branch.
LENGTH_DELTA = 64

MAX_URLS = 60
BATCH = 12


@dataclass(frozen=True)
class ObservedParam:
    """A parameter the app itself exposed, and where we saw it."""

    name: str
    example_url: str
    sources: tuple[str, ...] = ()
    values_seen: int = 1

    @property
    def notable(self) -> tuple[Severity, str] | None:
        return _NOTABLE.get(self.name.lower())


@dataclass(frozen=True)
class HiddenParam:
    """A parameter the app accepts but never published."""

    name: str
    url: str
    evidence: str
    severity: Severity = Severity.LOW
    reflected: bool = False

    @property
    def check_id(self) -> str:
        return "hidden-parameter-reflected" if self.reflected else "hidden-parameter"


@dataclass
class Baseline:
    """What a URL looks like with no extra parameters — the comparison point."""

    url: str
    status: int
    length: int
    body_sample: str = field(default="", repr=False)


def classify_name(name: str) -> tuple[Severity, str]:
    """What a parameter *name* means, independent of how it was discovered.

    Shared by the built-in prober and the arjun path so both engines describe the same
    parameter the same way — a finding's severity should not depend on which tool
    happened to find it.
    """
    return _NOTABLE.get(name.lower(), (Severity.LOW, "an undocumented parameter"))


def extract_observed(urls: list[str]) -> list[ObservedParam]:
    """Every parameter already present in the URLs we hold. Costs no requests.

    This is usually the larger half of the real surface and the honest place to start:
    the app told us these exist, so there is nothing to guess and nothing to probe.
    """
    seen: dict[str, dict] = {}
    for url in urls:
        query = urlsplit(url).query
        if not query:
            continue
        for name, values in parse_qs(query, keep_blank_values=True).items():
            entry = seen.setdefault(name, {"url": url, "values": set()})
            entry["values"].update(v for v in values if v)
    return [
        ObservedParam(
            name=name,
            example_url=data["url"],
            values_seen=len(data["values"]),
        )
        for name, data in sorted(seen.items())
    ]


def probe_url(url: str, params: list[str], *, value: str = PROBE_VALUE) -> str:
    """The URL with *params* appended, preserving whatever was already there."""
    parts = urlsplit(url)
    existing = parse_qs(parts.query, keep_blank_values=True)
    for name in params:
        existing.setdefault(name, [value])
    return urlunsplit(parts._replace(query=urlencode(existing, doseq=True)))


def _reflects(body: str, value: str) -> bool:
    return bool(body) and value in body


def analyse_batch(
    baseline: Baseline,
    params: list[str],
    status: int,
    body: str,
    *,
    value: str = PROBE_VALUE,
) -> bool:
    """Did adding *params* change the response at all?

    Returns True when the batch is worth splitting to find which parameter mattered.
    A batch that changed nothing eliminates every parameter in it at the cost of one
    request, which is what keeps this bounded.
    """
    if status != baseline.status:
        return True
    if abs(len(body) - baseline.length) >= LENGTH_DELTA:
        return True
    return _reflects(body, value)


def classify(
    name: str, baseline: Baseline, status: int, body: str, *, value: str = PROBE_VALUE
) -> HiddenParam | None:
    """Decide what a single confirmed parameter means."""
    reflected = _reflects(body, value)
    changed_status = status != baseline.status
    delta = len(body) - baseline.length

    if not (reflected or changed_status or abs(delta) >= LENGTH_DELTA):
        return None

    severity, what = classify_name(name)
    if reflected:
        # Reflection is not XSS — we submitted an inert alphabetic string and looked for
        # it in the response. It means the value reaches the output, which is where a
        # human should look next.
        severity = Severity.MEDIUM if severity is Severity.LOW else severity

    bits = []
    if changed_status:
        bits.append(f"the status changed from {baseline.status} to {status}")
    if abs(delta) >= LENGTH_DELTA:
        bits.append(f"the response length changed by {delta:+d} bytes")
    if reflected:
        bits.append("the submitted value appeared in the response body")

    return HiddenParam(
        name=name,
        url=baseline.url,
        severity=severity,
        reflected=reflected,
        evidence=(
            f"Adding ?{name}={value} to this URL is {what}: " + ", and ".join(bits) + ". "
            "The parameter is not linked or documented anywhere we crawled, so it is "
            "surface an attacker would have to find — and now has. This records only "
            "that the parameter is accepted and changes behaviour; nothing was submitted "
            "beyond an inert alphabetic string."
        ),
    )
