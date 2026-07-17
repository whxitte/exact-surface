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

import math
import re

from core.severity import Severity

# Substrings that never appear in a real credential but are ubiquitous in
# placeholder/sample values. Deliberately unambiguous: "test" and "1234" are NOT
# here because `sk_test_…` and real tokens legitimately contain them — a marker that
# risks dropping a real secret would defeat the point. (Idea from the ZeroPoint
# reference engine; adapted to Vantari's high-signal patterns.)
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

    Vantari's regex layer records hits independently of trufflehog's live
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
    """Return detected secrets as ``{kind, value, severity, source_locator}`` dicts.

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
            hits.append(
                {
                    "kind": kind,
                    "value": value,
                    "severity": severity,
                    "source_locator": source_locator,
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
