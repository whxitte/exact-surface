"""CVE/KEV feed parsing + confidence-scored matching (the flagship differentiator)."""

from __future__ import annotations

import pytest

from core.cpe import parse_tech, parse_version, version_in_range
from core.hashing import endpoint_fingerprint
from core.models import Endpoint
from core.severity import Severity
from core.tenant import TenantContext
from db.cves import CveMatchRepo
from db.endpoints import EndpointRepo
from modules.intelligence.cve_feed import parse_kev, parse_nvd
from modules.intelligence.cve_match import alertable, match_cves
from pipelines.cve_watch import run_cve_watch
from tests.fakes import FakeMongo

TENANT = TenantContext("t1", "u1")

NVD_PAYLOAD = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2020-1234",
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]},
                "references": [{"url": "https://nvd/CVE-2020-1234"}],
                "configurations": [
                    {
                        "nodes": [
                            {
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*",
                                        "versionEndExcluding": "5.5",
                                    }
                                ]
                            }
                        ]
                    }
                ],
            }
        }
    ]
}
KEV_PAYLOAD = {"vulnerabilities": [{"cveID": "CVE-2020-1234"}]}


# -- cpe parsing -------------------------------------------------------------
@pytest.mark.parametrize(
    "tech,expected",
    [
        ("WordPress 5.4", ("wordpress", "5.4")),
        ("nginx:1.18.0", ("nginx", "1.18.0")),
        ("PHP/7.4", ("php", "7.4")),
        ("nginx", ("nginx", None)),
    ],
)
def test_parse_tech(tech, expected):
    assert parse_tech(tech) == expected


def test_version_in_range():
    assert version_in_range("5.4", end_excl="5.5")
    assert not version_in_range("5.6", end_excl="5.5")
    assert version_in_range("1.2.3", start_incl="1.0.0", end_incl="2.0.0")
    assert version_in_range("5.4", exact="5.4")
    assert parse_version("nope") == ()


# -- feed parsing ------------------------------------------------------------
def test_parse_nvd_and_kev():
    records = parse_nvd(NVD_PAYLOAD)
    assert len(records) == 1
    r = records[0]
    assert r.cve_id == "CVE-2020-1234" and r.product == "wordpress"
    assert r.cvss == 9.8 and r.version_end_excl == "5.5"
    assert parse_kev(KEV_PAYLOAD) == {"CVE-2020-1234"}


# -- matching + confidence ---------------------------------------------------
def test_high_confidence_when_version_in_range():
    records = parse_nvd(NVD_PAYLOAD)
    items = [{"product": "wordpress", "version": "5.4", "asset_fingerprint": "a", "location": "u"}]
    m = match_cves(items, records, set())
    assert len(m) == 1 and m[0]["confidence"] == "high" and alertable(m[0])


def test_low_confidence_when_no_version():
    records = parse_nvd(NVD_PAYLOAD)
    items = [{"product": "wordpress", "version": None, "asset_fingerprint": "a", "location": "u"}]
    m = match_cves(items, records, set())
    assert m[0]["confidence"] == "low" and not alertable(m[0])


def test_no_match_when_version_not_affected():
    records = parse_nvd(NVD_PAYLOAD)
    items = [{"product": "wordpress", "version": "5.6", "asset_fingerprint": "a", "location": "u"}]
    assert match_cves(items, records, set()) == []


def test_kev_forces_high_and_escalates_severity():
    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2021-9",
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 4.0}}]},
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "cpeMatch": [
                                        {
                                            "vulnerable": True,
                                            "criteria": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
                                        }
                                    ]
                                }
                            ]
                        }
                    ],
                }
            }
        ]
    }
    records = parse_nvd(payload)
    items = [{"product": "nginx", "version": None, "asset_fingerprint": "a", "location": "u"}]
    m = match_cves(items, records, {"CVE-2021-9"})
    # even with no version, KEV membership forces high confidence + >= HIGH severity
    assert m[0]["confidence"] == "high" and m[0]["severity"].rank >= Severity.HIGH.rank


# -- pipeline ----------------------------------------------------------------
async def test_cve_watch_pipeline_alerts_only_high():
    mongo = FakeMongo()
    await EndpointRepo(mongo.collection("endpoints")).upsert(
        Endpoint(
            tenant_id="t1",
            program_id="p1",
            fingerprint=endpoint_fingerprint("p1", "GET", "https://app.customer.com"),
            url="https://app.customer.com",
            tech=["WordPress 5.4"],
        )
    )

    async def recent():
        return parse_nvd(NVD_PAYLOAD)

    async def kev():
        return parse_kev(KEV_PAYLOAD)

    res = await run_cve_watch(mongo=mongo, tenant=TENANT, program_id="p1", recent=recent, kev=kev)
    assert res["matches"] == 1 and res["new_alertable"] == 1
    assert res["alerts"][0]["cve_id"] == "CVE-2020-1234" and res["alerts"][0]["on_kev"] is True

    # idempotent: second run yields no new alerts
    res2 = await run_cve_watch(mongo=mongo, tenant=TENANT, program_id="p1", recent=recent, kev=kev)
    assert res2["new_alertable"] == 0
    assert await CveMatchRepo(mongo.collection("cve_matches")).count("t1") == 1
