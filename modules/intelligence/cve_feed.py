"""CVE/KEV feed client (module 24): NVD 2.0 + CISA KEV.

Fetches recent CVEs (with affected-version ranges parsed from CPE match criteria)
and the CISA Known Exploited Vulnerabilities set. Both fetchers are injected so the
matcher and pipeline test offline. Parsing is tolerant: a record we cannot parse is
skipped, never fatal.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from core.cpe import normalize_product
from core.logging import logger

Fetch = Callable[[str], Awaitable[dict]]

NVD_RECENT_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=200"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


@dataclass(frozen=True)
class CveRecord:
    cve_id: str
    product: str
    cvss: float | None
    version_start_incl: str | None = None
    version_end_excl: str | None = None
    version_end_incl: str | None = None
    exact_version: str | None = None
    references: tuple[str, ...] = ()


def _extract_cvss(metrics: dict) -> float | None:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for m in metrics.get(key, []):
            score = (m.get("cvssData") or {}).get("baseScore")
            if score is not None:
                return float(score)
    return None


def parse_nvd(payload: dict) -> list[CveRecord]:
    """Parse NVD 2.0 JSON into CveRecords (one per affected CPE match)."""
    records: list[CveRecord] = []
    for item in payload.get("vulnerabilities", []):
        cve = item.get("cve") or {}
        cve_id = cve.get("id")
        if not cve_id:
            continue
        cvss = _extract_cvss(cve.get("metrics") or {})
        refs = tuple(r.get("url", "") for r in (cve.get("references") or []) if r.get("url"))
        for config in cve.get("configurations") or []:
            for node in config.get("nodes") or []:
                for match in node.get("cpeMatch") or []:
                    if not match.get("vulnerable", False):
                        continue
                    product = _product_from_cpe(match.get("criteria", ""))
                    if not product:
                        continue
                    records.append(
                        CveRecord(
                            cve_id=cve_id,
                            product=product,
                            cvss=cvss,
                            version_start_incl=match.get("versionStartIncluding"),
                            version_end_excl=match.get("versionEndExcluding"),
                            version_end_incl=match.get("versionEndIncluding"),
                            exact_version=_exact_from_cpe(match.get("criteria", "")),
                            references=refs,
                        )
                    )
    return records


def _product_from_cpe(cpe: str) -> str:
    # cpe:2.3:a:vendor:product:version:...
    parts = cpe.split(":")
    return normalize_product(parts[4]) if len(parts) > 5 else ""


def _exact_from_cpe(cpe: str) -> str | None:
    parts = cpe.split(":")
    if len(parts) > 5 and parts[5] not in ("*", "-", ""):
        return parts[5]
    return None


def parse_kev(payload: dict) -> set[str]:
    """Parse the CISA KEV JSON into a set of CVE ids."""
    return {v["cveID"] for v in payload.get("vulnerabilities", []) if v.get("cveID")}


async def _default_fetch(url: str) -> dict:
    import aiohttp

    async with aiohttp.ClientSession() as session:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
            return await resp.json(content_type=None)


async def fetch_recent_cves(*, fetch: Fetch = _default_fetch) -> list[CveRecord]:
    try:
        return parse_nvd(await fetch(NVD_RECENT_URL))
    except Exception as exc:  # noqa: BLE001 - feed outage degrades to empty, not fatal
        logger.warning("NVD fetch failed: {}", exc)
        return []


async def fetch_kev(*, fetch: Fetch = _default_fetch) -> set[str]:
    try:
        return parse_kev(await fetch(KEV_URL))
    except Exception as exc:  # noqa: BLE001
        logger.warning("KEV fetch failed: {}", exc)
        return set()
