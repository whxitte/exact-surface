"""Exposed-secret detection + masking policy (§9c, ADR-0006).

Two responsibilities, both pure:

* :func:`find_secrets` — regex detection of high-signal secret types in text
  (JS bundles, archived responses, exposed config).
* :func:`mask` — turn a secret into a safe display hint (``AKIA••••••••7Q``).

Plaintext never leaves this boundary as-is: callers store the *masked* value plus
a keyed hash (``core.hashing.keyed_hash``), never the raw secret (ADR-0006). The
patterns are deliberately conservative — a low false-positive rate matters more
than catching every exotic token, because a noisy secret scanner is untrustworthy.
"""

from __future__ import annotations

import base64
import json
import math
import re
import time

from core.severity import Severity

# Substrings that never appear in a real credential but are ubiquitous in
# placeholder/sample values. Deliberately unambiguous: "test" and "1234" are NOT
# here because `sk_test_…` and real tokens legitimately contain them — a marker that
# risks dropping a real secret would defeat the point. (Idea from the ZeroPoint
# reference engine; adapted to ExactSurface's high-signal patterns.)
_PLACEHOLDER_MARKERS = (
    "your_",
    "your-",
    "yourkey",
    "<your",
    "placeholder",
    "example",
    "changeme",
    "change_me",
    "change-me",
    "replace_me",
    "replace-me",
    "insert_",
    "dummy",
    "redacted",
    "xxxxxx",
    "lorem",
    "samplekey",
    "notarealkey",
)

_URL_PREFIXES = ("http://", "https://", "//", "ws://", "wss://")

#: Entropy floor for the catch-all ``generic_secret`` pattern ONLY. The specific
#: patterns (AKIA/ghp_/sk_live_/AIza/private-key headers) are self-validating by
#: their prefix and must never be entropy-filtered, or a real-but-low-entropy key
#: would be dropped as a false negative. A real 16+ char secret sits well above 3.0;
#: this trims repetitive junk like "aaaaaaaaaaaaaaaa" / "1234123412341234".
_GENERIC_ENTROPY_FLOOR = 3.0


def _shannon_entropy(value: str) -> float:
    """Bits/char of a string. Low → repetitive/placeholder; high → random secret."""
    if not value:
        return 0.0
    length = len(value)
    counts = {ch: value.count(ch) for ch in set(value)}
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def _is_false_positive(kind: str, value: str) -> bool:
    """True if a regex match is almost certainly not a live secret.

    ExactSurface's regex layer records hits independently of trufflehog's live
    verification, so without this a bundle with ``apiKey = "YOUR_API_KEY_HERE"``
    produced a real finding — directly inflating the §15 false-positive rate, the
    make-or-break metric. Kept conservative: the URL/placeholder checks are safe for
    every pattern, and entropy is applied only to the catch-all.
    """
    if value.startswith(_URL_PREFIXES):
        return True  # a URL is not a credential (generic patterns can match apiUrl=…)
    low = value.lower()
    if any(marker in low for marker in _PLACEHOLDER_MARKERS):
        return True
    if kind == "generic_secret" and _shannon_entropy(value) < _GENERIC_ENTROPY_FLOOR:
        return True
    return False


# --------------------------------------------------------------------------- #
# Semantic classification — a regex match is a candidate, not a verdict.
# --------------------------------------------------------------------------- #
# Claims that make a JWT interesting: it names or entitles a principal. A token with
# only these is an identity/access token worth a look.
_JWT_PRIVILEGED_CLAIMS = frozenset(
    {
        "email",
        "role",
        "roles",
        "scope",
        "scopes",
        "name",
        "preferred_username",
        "groups",
        "upn",
        "unique_name",
        "given_name",
        "family_name",
        "cognito:groups",
        "permissions",
    }
)

#: Markers that put a Google API key in a Firebase-web-config context, where the key is
#: public by design (it identifies the project; access is gated by Security Rules).
_FIREBASE_MARKERS = (
    "authdomain",
    "firebaseapp.com",
    "firebaseio.com",
    "firebaseconfig",
    "firebase",
)


def _b64url(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def _decode_jwt(token: str) -> tuple[dict, dict] | None:
    try:
        header_b64, payload_b64, _ = token.split(".")
        header = json.loads(_b64url(header_b64))
        payload = json.loads(_b64url(payload_b64))
    except Exception:  # noqa: BLE001 - malformed is handled by the caller
        return None
    return (header, payload) if isinstance(payload, dict) else None


def classify_jwt(value: str, *, now: float | None = None) -> tuple[Severity, str] | None:
    """A JWT found in a response is a *candidate*. Return (severity, note) or None to drop.

    A JWT is rarely the secret — the signing key is. Most JWTs a scan sees are the
    short-lived session/visitor tokens an app hands every browser (Wix, Firebase, etc.),
    which are public by design and pure noise. So:

    * expired (``exp`` in the past) → drop; an expired token is not a live credential.
    * carries identity/privilege claims (email, role, scope, …) and is not expired →
      MEDIUM, because it may grant access and is worth verifying.
    * anything else (a bare session token: only iat/exp/jti/sub/data) → drop.
    """
    now = now or time.time()
    decoded = _decode_jwt(value)
    if decoded is None:
        return None  # not actually a JWT despite the shape
    _header, payload = decoded
    exp = payload.get("exp")
    if isinstance(exp, (int, float)) and exp < now:
        return None
    if {k.lower() for k in payload} & _JWT_PRIVILEGED_CLAIMS:
        return (
            Severity.MEDIUM,
            "A JWT carrying identity or privilege claims is exposed here. Decode it to "
            "confirm what it grants and whether it is still valid — a live, privileged "
            "token is a real credential; a public/anonymous one is not.",
        )
    return None


def classify_google_key(value: str, text: str, source_locator: str) -> tuple[Severity, str]:
    """Firebase web API keys (AIza… in a Firebase config) are public by design, not a
    leak. Any other Google API key may be an unrestricted, billable key and stays HIGH."""
    haystack = (source_locator + " " + text).lower()
    if any(m in haystack for m in _FIREBASE_MARKERS):
        return (
            Severity.INFO,
            "Firebase Web API key — public by design: it identifies the project, and "
            "access is controlled by Firebase Security Rules, not by keeping this secret. "
            "Not a leak. Worth confirming your Security Rules are restrictive and the key "
            "has API/referrer restrictions set in the Google Cloud console.",
        )
    return (Severity.HIGH, "")


# (kind, pattern, severity). Patterns with a capture group report that group;
# otherwise the whole match. Ordered high-signal first.
_PATTERNS: tuple[tuple[str, re.Pattern[str], Severity], ...] = (
    (
        "private_key",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
        Severity.CRITICAL,
    ),
    (
        "aws_secret_key",
        re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+]{40})"),
        Severity.CRITICAL,
    ),
    (
        "stripe_secret_key",
        re.compile(r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{24,}\b"),
        Severity.CRITICAL,
    ),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), Severity.HIGH),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), Severity.HIGH),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), Severity.HIGH),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), Severity.HIGH),
    (
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
        Severity.MEDIUM,
    ),
    (
        "generic_secret",
        re.compile(
            r"(?i)(?:api[_-]?key|secret|passwd|password|token)\s*[=:]\s*"
            r"['\"]([A-Za-z0-9_\-]{16,})['\"]"
        ),
        Severity.MEDIUM,
    ),
)


def find_secrets(text: str, source_locator: str) -> list[dict]:
    """Return detected secrets as ``{kind, value, severity, source_locator, note}`` dicts.

    A regex match is a candidate; a per-kind classifier then decides the verdict — it may
    drop the hit (an expired or anonymous JWT, an expected public key) or set a severity
    and note from context. This is what keeps the scanner from reporting the public
    tokens every modern site hands its own browser (Firebase web keys, Wix/Auth0 session
    JWTs) as leaks, which is the difference between a signal and noise.

    De-duplicates within a single source so one key repeated in a file is one hit.
    """
    seen: set[tuple[str, str]] = set()
    hits: list[dict] = []
    for kind, pattern, severity in _PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(match.lastindex) if match.lastindex else match.group(0)
            key = (kind, value)
            if key in seen:
                continue
            seen.add(key)
            if _is_false_positive(kind, value):
                continue  # placeholder / URL / no-entropy — not a live secret (§15 FP rate)

            note = ""
            if kind == "jwt":
                verdict = classify_jwt(value)
                if verdict is None:
                    continue  # expired or a bare session/anonymous token — not a leak
                severity, note = verdict
            elif kind == "google_api_key":
                severity, note = classify_google_key(value, text, source_locator)

            hits.append(
                {
                    "kind": kind,
                    "value": value,
                    "severity": severity,
                    "source_locator": source_locator,
                    "note": note,
                }
            )
    return hits


def mask(value: str) -> str:
    """Safe display hint: keep a few edge chars, redact the middle."""
    if not value:
        return ""
    if len(value) <= 8:
        return value[0] + "•" * (len(value) - 1)
    return f"{value[:4]}{'•' * 8}{value[-2:]}"
