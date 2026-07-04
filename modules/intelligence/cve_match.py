"""CVE matcher with confidence scoring (module 21 policy, §6).

The single most important knob for EASM credibility is false-positive rate. So:

* a product match with a concrete, in-affected-range version → **high** confidence;
* a product match with no version we can confirm → **low** (accumulates silently,
  never alerts by default);
* any CISA-KEV-listed CVE → escalated to **high** confidence and >= HIGH severity,
  regardless — known-exploited beats theoretical.

Pure function: given the fingerprinted tech and the feed, it returns match dicts.
Persistence, alerting, and priority-scan triggering are the pipeline's job.
"""

from __future__ import annotations

from core.cpe import to_cpe, version_in_range
from core.severity import escalate_for_kev, from_cvss


def match_cves(tech_items: list[dict], cve_records: list, kev: set[str]) -> list[dict]:
    """Match fingerprinted tech against CVE records.

    ``tech_items``: ``[{product, version, asset_fingerprint, location}, ...]``.
    Returns match dicts with ``confidence`` in {low, high} and KEV-aware severity.
    """
    by_product: dict[str, list] = {}
    for record in cve_records:
        by_product.setdefault(record.product, []).append(record)

    matches: list[dict] = []
    for item in tech_items:
        product = item.get("product") or ""
        version = item.get("version")
        for record in by_product.get(product, []):
            confidence = _confidence(version, record)
            if confidence is None:
                continue  # version present but not in the affected range → no match
            on_kev = record.cve_id in kev
            severity = escalate_for_kev(from_cvss(record.cvss), on_kev)
            if on_kev:
                confidence = "high"
            matches.append(
                {
                    "cve_id": record.cve_id,
                    "product": product,
                    "version": version,
                    "cpe": to_cpe(product, version),
                    "asset_fingerprint": item.get("asset_fingerprint", ""),
                    "location": item.get("location", ""),
                    "cvss": record.cvss,
                    "on_kev": on_kev,
                    "confidence": confidence,
                    "severity": severity,
                    "references": list(record.references),
                }
            )
    return matches


def _confidence(version: str | None, record) -> str | None:
    """Return 'high' / 'low', or None if the version is present but not affected."""
    if version is None:
        return "low"  # product-only match; cannot confirm the vulnerable version
    if version_in_range(
        version,
        start_incl=record.version_start_incl,
        end_excl=record.version_end_excl,
        end_incl=record.version_end_incl,
        exact=record.exact_version,
    ):
        return "high"
    return None


def alertable(match: dict) -> bool:
    """Only high-confidence matches (which includes all KEV) alert by default."""
    return match.get("confidence") == "high"
