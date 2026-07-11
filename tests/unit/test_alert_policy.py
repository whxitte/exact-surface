"""Alert-policy resolution, port-spec matching, and notify enforcement."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from core.alert_policy import (
    DEFAULT_ALERT_POLICY,
    clean_port_spec,
    effective_alert_policy,
    meets_severity_floor,
    port_matches,
    sanitize_alert_policy,
)
from core.models import (
    Asset,
    ChannelType,
    Finding,
    NotificationChannel,
    Port,
    Program,
)
from core.severity import Severity
from core.tenant import TenantContext
from db.assets import AssetRepo
from db.findings import FindingRepo
from db.notifications import NotificationChannelRepo
from db.ports import PortRepo
from db.programs import ProgramRepo
from modules.notification.base import Senders
from pipelines.notify import run_notify
from tests.fakes import FakeMongo

TENANT = TenantContext("t1", "u1")
BASELINE = datetime(2026, 7, 1, tzinfo=UTC)


# -- policy resolution -------------------------------------------------------
def test_clean_port_spec_drops_invalid():
    assert clean_port_spec("80, 22,1-100,x,70000") == "80,22,1-100"
    assert clean_port_spec("") == ""


def test_port_matches_lists_ranges_and_any():
    assert port_matches("22,80,443", 80)
    assert not port_matches("22,80,443", 8080)
    assert port_matches("8000-8100", 8080)
    assert port_matches("", 12345)  # empty spec = any port


def test_sanitize_drops_unknown_and_bad():
    p = sanitize_alert_policy(
        {"finding_min_severity": "nope", "alert_findings": "yes", "junk": 1, "cve_min_cvss": 99}
    )
    assert "finding_min_severity" not in p  # invalid severity dropped
    assert p["alert_findings"] is True and "junk" not in p
    assert p["cve_min_cvss"] == 10.0  # clamped to [0, 10]


def test_effective_policy_precedence():
    eff = effective_alert_policy(
        program_overrides={"finding_min_severity": "critical"},
        tenant_defaults={"finding_min_severity": "low", "alert_leaks": False},
    )
    assert eff["finding_min_severity"] == "critical"  # program wins over tenant
    assert eff["alert_leaks"] is False  # tenant override kept
    assert eff["alert_findings"] == DEFAULT_ALERT_POLICY["alert_findings"]  # built-in default


def test_meets_severity_floor():
    policy = {"finding_min_severity": "high"}
    assert meets_severity_floor("critical", policy)
    assert not meets_severity_floor("medium", policy)


# -- notify enforcement ------------------------------------------------------
class CaptureHttp:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []

    async def __call__(self, url: str, payload: dict) -> int:
        self.calls.append((url, payload))
        return 204


def _senders() -> tuple[Senders, CaptureHttp]:
    http = CaptureHttp()
    return Senders(http=http), http


async def _seed_program(mongo, *, baseline: datetime | None, policy: dict):
    await ProgramRepo.from_mongo(mongo).save(
        Program(
            tenant_id="t1",
            program_id="p1",
            apex_domain="acme.com",
            verified=True,
            alert_policy=policy,
            initial_scan_completed_at=baseline,
        )
    )
    await NotificationChannelRepo.from_mongo(mongo).save(
        NotificationChannel(
            tenant_id="t1",
            channel_id="c1",
            name="ops",
            type=ChannelType.DISCORD,
            min_severity=Severity.INFO,
            config={"webhook_url": "https://d/hook"},
        )
    )


async def _set_first_seen(mongo, coll: str, fp: str, when: datetime):
    await mongo.collection(coll).update_one({"fingerprint": fp}, {"$set": {"first_seen": when}})


async def test_new_subdomain_alert_gated_by_baseline():
    mongo = FakeMongo()
    await _seed_program(mongo, baseline=BASELINE, policy={"finding_min_severity": "info"})
    repo = AssetRepo.from_mongo(mongo)
    await repo.upsert(
        Asset(tenant_id="t1", program_id="p1", fingerprint="old", hostname="old.acme.com")
    )
    await _set_first_seen(mongo, "assets", "old", BASELINE - timedelta(days=1))
    await repo.upsert(
        Asset(tenant_id="t1", program_id="p1", fingerprint="new", hostname="new.acme.com")
    )
    await _set_first_seen(mongo, "assets", "new", BASELINE + timedelta(days=1))

    senders, http = _senders()
    res = await run_notify(mongo=mongo, tenant=TENANT, program_id="p1", senders=senders)
    assert res["delivered"] == 1
    blob = json.dumps(http.calls)
    assert "new.acme.com" in blob and "old.acme.com" not in blob  # baseline subdomain not alerted


async def test_new_subdomain_suppressed_without_baseline():
    mongo = FakeMongo()
    await _seed_program(mongo, baseline=None, policy={})  # first scan — no baseline yet
    await AssetRepo.from_mongo(mongo).upsert(
        Asset(tenant_id="t1", program_id="p1", fingerprint="a", hostname="a.acme.com")
    )
    senders, http = _senders()
    res = await run_notify(mongo=mongo, tenant=TENANT, program_id="p1", senders=senders)
    assert res["delivered"] == 0 and http.calls == []


async def test_new_port_respects_port_filter():
    mongo = FakeMongo()
    await _seed_program(
        mongo, baseline=BASELINE, policy={"port_filter": "22,3389", "alert_new_assets": False}
    )
    repo = PortRepo.from_mongo(mongo)
    for fp, port in [("p22", 22), ("p80", 80)]:
        await repo.upsert(
            Port(tenant_id="t1", program_id="p1", fingerprint=fp, ip="1.1.1.1", port=port)
        )
        await _set_first_seen(mongo, "ports", fp, BASELINE + timedelta(days=1))

    senders, http = _senders()
    res = await run_notify(mongo=mongo, tenant=TENANT, program_id="p1", senders=senders)
    assert res["delivered"] == 1  # only port 22 matches the filter
    blob = json.dumps(http.calls)
    assert "22/tcp" in blob and "80/tcp" not in blob


async def test_finding_floor_and_family_toggle():
    mongo = FakeMongo()
    await _seed_program(
        mongo, baseline=None, policy={"finding_min_severity": "high", "alert_secrets": False}
    )
    repo = FindingRepo.from_mongo(mongo)
    await repo.upsert(
        Finding(
            tenant_id="t1",
            program_id="p1",
            fingerprint="lo",
            check_id="x",
            module="nuclei",
            location="a",
            name="low one",
            severity=Severity.LOW,
        )
    )
    await repo.upsert(
        Finding(
            tenant_id="t1",
            program_id="p1",
            fingerprint="hi",
            check_id="y",
            module="nuclei",
            location="b",
            name="high one",
            severity=Severity.HIGH,
        )
    )
    senders, http = _senders()
    res = await run_notify(mongo=mongo, tenant=TENANT, program_id="p1", senders=senders)
    assert res["delivered"] == 1  # low filtered out by the floor
    assert "high one" in json.dumps(http.calls) and "low one" not in json.dumps(http.calls)
