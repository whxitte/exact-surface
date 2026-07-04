"""Finding severity + CVSS/EPSS mapping.

Severity drives triage order and per-channel notification thresholds. We keep a
single ordered enum and a CVSS-band mapping so a numeric CVSS from a template or
CVE feed lands in a consistent bucket across the product.
"""

from __future__ import annotations

from enum import Enum


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _ORDER[self]


_ORDER: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def from_cvss(score: float | None) -> Severity:
    """Map a CVSS base score (0.0–10.0) to a severity band (CVSS v3 ranges)."""
    if score is None:
        return Severity.INFO
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.INFO


def escalate_for_kev(base: Severity, on_kev: bool) -> Severity:
    """A CISA-KEV-listed match is escalated to at least HIGH (§module 21 policy)."""
    if on_kev and base.rank < Severity.HIGH.rank:
        return Severity.HIGH
    return base


def meets_threshold(sev: Severity, threshold: Severity) -> bool:
    """True if *sev* is at or above *threshold* (for notification routing)."""
    return sev.rank >= threshold.rank
