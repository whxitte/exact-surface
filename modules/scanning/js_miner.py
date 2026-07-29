"""JavaScript mining — the highest-yield technique in modern bug hunting.

A single-page app ships its entire routing table to the browser. Inside those bundles
are the API paths the UI calls, internal hostnames, admin routes that never appear in a
crawl, feature flags, and the occasional forgotten debug endpoint. Hunters spend hours
reading minified JS by hand precisely because it is where the good findings are; this
module automates that pass.

What it extracts, per file:

* **Paths / endpoints** — ``/api/internal/v2/users``, route tables, fetch/axios targets.
* **Absolute URLs and hostnames** — often revealing subdomains that DNS enumeration
  never returned (internal APIs, staging hosts, third-party services in use).
* **Source-map references** — a published ``.map`` hands over the original, unminified
  source, which is a finding in itself.
* **Interesting markers** — admin/debug/internal/token routes worth a human's attention.

Design notes:

* The regexes are a hardened superset of the LinkFinder patterns that hunters have used
  for years, plus URL/hostname extraction and framework-route patterns.
* **Noise control is the hard part**, not extraction. Minified bundles are full of
  strings that look like paths (MIME types, CSS units, dates, version strings, base64).
  Everything here is filtered through :func:`_is_plausible_path`, and library files are
  skipped wholesale — a tool that reports 4,000 junk "endpoints" is worse than useless.
* Pure and offline: :func:`mine` takes text, returns structures. The pipeline does I/O.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

# --------------------------------------------------------------------------- #
# Extraction patterns
# --------------------------------------------------------------------------- #
#: Quoted strings that look like a path or URL. This is the LinkFinder-style core:
#: match inside quotes, require either a leading slash, a scheme, or a file extension.
_LINK_RE = re.compile(
    r"""(?:"|'|`)                       # opening quote
        (
          (?:https?:)?//[\w\-.:@]+[^"'`\s]*   # absolute or protocol-relative URL
          |
          /[\w\-./]{2,}(?:\?[^"'`\s]*)?       # rooted path, optionally with a query
          |
          [\w\-./]+/[\w\-./]+\.(?:json|xml|php|asp|aspx|jsp|do|action|graphql)
                                              # relative path to a dynamic resource
        )
        (?:"|'|`)                       # closing quote
    """,
    re.VERBOSE,
)

#: Route/endpoint assignments the frameworks generate — catches paths that are built
#: from variables and so never appear as one complete quoted string.
_ROUTE_HINT_RE = re.compile(
    r"""(?:path|url|endpoint|route|uri|baseURL|apiUrl|api_url)\s*[:=]\s*
        (?:"|'|`)([^"'`\s]{2,200})(?:"|'|`)""",
    re.VERBOSE | re.IGNORECASE,
)

#: fetch("...") / axios.get("...") / $.ajax({url:"..."}) style calls.
_CALL_RE = re.compile(
    r"""(?:fetch|axios(?:\.\w+)?|\.open|request|ajax)\s*\(\s*
        (?:"|'|`)([^"'`\s]{2,200})(?:"|'|`)""",
    re.VERBOSE | re.IGNORECASE,
)

#: //# sourceMappingURL=app.js.map — a published map exposes the original source.
_SOURCEMAP_RE = re.compile(r"//[#@]\s*sourceMappingURL\s*=\s*(\S+)")

#: Hostnames, extracted ONLY from a URL context (``//host`` or ``scheme://host``).
#: Matching bare dotted strings looks tempting but is catastrophic in minified code:
#: ``array.prototype.find``, ``object.entries`` and every ``model.field.subfield`` in
#: the app read as "hostnames". A host the app actually talks to appears in a URL.
_HOST_RE = re.compile(
    r"//([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)+)(?=[/:\"'`?\s]|$)",
    re.IGNORECASE,
)

#: Public suffixes we accept for an extracted hostname. Deliberately a fixed list:
#: it is the difference between "a host" and "a property chain that ends in .name".
_VALID_TLDS: frozenset[str] = frozenset(
    """com net org io dev app co uk us ca au de fr nl eu in jp cn br it es se no fi dk
    pl ru ch at be cz gr pt ie nz za mx ar cl kr sg hk tw th my id ph vn tr il ae sa
    ai cloud tech online site xyz info biz me tv cc gg sh st ly to fm am pro live
    world space store shop blog wiki news email cool link click page host press
    agency company solutions services digital network systems software media group
    center global today report zone team works studio design partners capital fund
    edu gov mil int arpa local internal test example invalid localhost""".split()
)

# --------------------------------------------------------------------------- #
# Noise control
# --------------------------------------------------------------------------- #
#: Filenames that are third-party libraries. Mining them yields the library's own
#: routes, not the target's — pure noise, and a lot of it.
_LIBRARY_MARKERS: tuple[str, ...] = (
    "jquery", "bootstrap", "react-dom", "react.production", "angular", "vue.runtime",
    "lodash", "moment", "polyfill", "runtime~", "chunk-vendors", "modernizr",
    "popper", "tailwind", "fontawesome", "swiper", "gtm.js", "analytics.js",
    "recaptcha", "hotjar", "intercom", "stripe.js", "googletagmanager",
    "moment", "axios", "core-js", "zone.js", "rxjs", "d3.", "chart.", "three.",
    "highcharts", "pdf.worker", "mapbox", "leaflet", "sentry", "datadog", "segment",
)

#: Extensions that are assets, not endpoints. **Script files belong here**: a path to
#: another bundle is not attack surface, and treating one as an endpoint is how
#: ``/js/admin.6fd71600.js`` ends up flagged "admin" hundreds of times.
_ASSET_EXT: frozenset[str] = frozenset(
    {"png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "css", "woff", "woff2", "ttf",
     "eot", "otf", "mp4", "webm", "mp3", "pdf", "map", "txt", "md", "avif",
     "js", "mjs", "cjs", "jsx", "ts", "tsx", "vue", "scss", "less", "wasm"}
)

#: Hosts that only ever appear as XML/schema namespaces or standards references —
#: never attack surface, and common enough in bundles to matter.
_NAMESPACE_HOSTS: tuple[str, ...] = (
    "w3.org", "schema.org", "purl.org", "xmlns.com", "ns.adobe.com",
    "sourceforge.net/xml", "docbook.org", "openxmlformats.org",
)

#: Strings that look like paths but never are.
_NOISE_RE = re.compile(
    r"""^(?:
        /\d+(?:\.\d+)*$                 # version-ish  /1.2.3
        | /[a-f0-9]{16,}$               # hashes
        | //?(?:www\.)?w3\.org          # XML namespaces
        | /(?:px|em|rem|vh|vw|%|deg)$   # CSS units
        | /(?:[A-Za-z]:)?/*$            # slashes only
    )""",
    re.VERBOSE | re.IGNORECASE,
)

#: Paths that deserve a human's eyes first, mapped to why.
_INTEREST: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"/(?:admin|administrator|manage|console|dashboard)\b", re.I), "admin"),
    (re.compile(r"/(?:internal|private|priv|secret|hidden)\b", re.I), "internal"),
    (re.compile(r"/(?:debug|test|dev|staging|sandbox|beta)\b", re.I), "non-production"),
    (re.compile(r"/(?:auth|login|logout|token|oauth|session|sso|saml)\b", re.I), "auth"),
    (re.compile(r"/(?:upload|file|import|export|backup|dump)\b", re.I), "file-handling"),
    (re.compile(r"/(?:graphql|graphiql)\b", re.I), "graphql"),
    (re.compile(r"/(?:swagger|openapi|api-docs|redoc)\b", re.I), "api-docs"),
    (re.compile(r"/(?:user|account|profile|customer)s?/", re.I), "user-data"),
    (re.compile(r"/(?:payment|billing|invoice|charge|card)\b", re.I), "payment"),
    (re.compile(r"/\.(?:git|env|svn|ds_store)", re.I), "exposure"),
    (re.compile(r"/(?:key|secret|credential|password|passwd)\b", re.I), "credentials"),
    (re.compile(r"/api/", re.I), "api"),
)


#: Directory segments that mean "not the app's own code". Locale/i18n bundles are the
#: worst offenders: a single library ships ~100 of them, each yielding identical noise.
_LIBRARY_PATH_SEGMENTS: tuple[str, ...] = (
    "/locale/", "/locales/", "/i18n/", "/lang/", "/langs/", "/translations/",
    "/vendor/", "/vendors/", "/node_modules/", "/dist/lib/", "/polyfills/",
)


def is_library_file(url: str) -> bool:
    """True for third-party bundles, which are noise to mine — their routes belong to
    the library, not to the target."""
    path = urlsplit(url).path.lower()
    name = path.rsplit("/", 1)[-1]
    if any(seg in path for seg in _LIBRARY_PATH_SEGMENTS):
        return True
    if any(marker in name for marker in _LIBRARY_MARKERS):
        return True
    # A percent-encoded "filename" is a mangled string that was mistaken for a URL
    # upstream (e.g. a package description ending in "node.js"), never a real bundle.
    return "%20" in name


def _is_plausible_path(candidate: str) -> bool:
    """The noise filter. Everything extracted passes through here."""
    if not candidate or len(candidate) < 2 or len(candidate) > 300:
        return False
    if _NOISE_RE.match(candidate):
        return False
    if candidate.startswith(("data:", "blob:", "javascript:", "mailto:", "tel:", "#")):
        return False
    lowered = candidate.lower()
    if any(ns in lowered for ns in _NAMESPACE_HOSTS):
        return False
    # Reject asset files — they are content, not attack surface.
    path = urlsplit(candidate).path
    ext = path.rsplit(".", 1)[-1].lower() if "." in path.rsplit("/", 1)[-1] else ""
    if ext in _ASSET_EXT:
        return False
    # Reject strings that are mostly punctuation/escapes (minifier artefacts).
    alnum = sum(c.isalnum() for c in candidate)
    return alnum >= max(2, len(candidate) // 3)


def classify(path: str) -> list[str]:
    """Why this path is interesting, as zero or more tags."""
    return [tag for pattern, tag in _INTEREST if pattern.search(path)]


# --------------------------------------------------------------------------- #
# Results
# --------------------------------------------------------------------------- #
@dataclass
class MinedItem:
    """One thing found inside a JS file."""

    value: str  # the path or URL as extracted
    kind: str  # "path" | "url" | "hostname"
    tags: list[str] = field(default_factory=list)  # admin, api, auth, …
    absolute: str | None = None  # resolved against the JS file's origin, when possible


@dataclass
class MinedFile:
    url: str
    size: int
    items: list[MinedItem] = field(default_factory=list)
    hostnames: list[str] = field(default_factory=list)
    source_map: str | None = None

    @property
    def interesting(self) -> list[MinedItem]:
        return [i for i in self.items if i.tags]


def mine(js_text: str, source_url: str, *, own_domains: tuple[str, ...] = ()) -> MinedFile:
    """Extract everything of interest from one JavaScript file.

    ``own_domains`` (the program's apexes) marks which discovered hostnames belong to
    the target — those are new attack surface; the rest are third-party dependencies,
    which are useful context but not the customer's to fix.
    """
    result = MinedFile(url=source_url, size=len(js_text))
    origin = f"{urlsplit(source_url).scheme}://{urlsplit(source_url).netloc}"

    raw: set[str] = set()
    for pattern in (_LINK_RE, _ROUTE_HINT_RE, _CALL_RE):
        for match in pattern.finditer(js_text):
            raw.add(match.group(1).strip())

    seen: set[str] = set()
    for candidate in sorted(raw):
        if not _is_plausible_path(candidate):
            continue
        if candidate in seen:
            continue
        seen.add(candidate)

        is_url = candidate.startswith(("http://", "https://", "//"))
        absolute = None
        if is_url:
            absolute = "https:" + candidate if candidate.startswith("//") else candidate
        elif candidate.startswith("/"):
            absolute = urljoin(origin + "/", candidate)

        result.items.append(
            MinedItem(
                value=candidate,
                kind="url" if is_url else "path",
                tags=classify(candidate),
                absolute=absolute,
            )
        )

    # Hostnames: everything that looks like a domain, minus the file's own host.
    self_host = urlsplit(source_url).hostname or ""
    hosts: set[str] = set()
    for match in _HOST_RE.finditer(js_text):
        host = match.group(1).lower().strip(".")
        if host == self_host or "." not in host:
            continue
        tld = host.rsplit(".", 1)[-1]
        # Must end in a real public suffix. Without this, every dotted identifier in
        # minified code (`array.prototype.find`) is reported as a host.
        if tld not in _VALID_TLDS:
            continue
        hosts.add(host)
    result.hostnames = sorted(hosts)

    sm = _SOURCEMAP_RE.search(js_text)
    if sm:
        ref = sm.group(1).strip()
        result.source_map = ref if ref.startswith("http") else urljoin(source_url, ref)

    # Mark items belonging to the target's own domains — the ones that matter most.
    if own_domains:
        for item in result.items:
            host = urlsplit(item.absolute or "").hostname or ""
            if host and any(host == d or host.endswith("." + d) for d in own_domains):
                if "own-domain" not in item.tags:
                    item.tags.append("own-domain")
    return result


def new_hostnames(
    files: list[MinedFile], known: set[str], own_domains: tuple[str, ...]
) -> list[str]:
    """Hostnames found in JS that belong to the target but weren't already discovered.

    This is the compounding part: JS routinely names internal or staging hosts that no
    passive source lists, and feeding them back into the pipeline finds real assets.
    """
    out: set[str] = set()
    for f in files:
        for host in f.hostnames:
            if host in known:
                continue
            if any(host == d or host.endswith("." + d) for d in own_domains):
                out.add(host)
    return sorted(out)


def discovered_paths(files: list[MinedFile], *, limit: int = 2000) -> list[str]:
    """Distinct rooted paths, most-interesting first — fed to content discovery so the
    next run probes what the app itself says exists."""
    scored: dict[str, int] = {}
    for f in files:
        for item in f.items:
            if item.kind != "path" or not item.value.startswith("/"):
                continue
            scored[item.value] = max(scored.get(item.value, 0), len(item.tags))
    ordered = sorted(scored.items(), key=lambda kv: (-kv[1], kv[0]))
    return [path for path, _ in ordered[:limit]]
