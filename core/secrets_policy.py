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

import re

from core.severity import Severity

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
