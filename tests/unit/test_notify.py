"""Notifications: channel formatting, severity threshold, masking, alert-once."""

from __future__ import annotations

import json

from core.models import (
    ChannelType,
    CveMatch,
    ExposedSecret,
    Finding,
    NotificationChannel,
    Program,
)
from core.severity import Severity
from core.tenant import TenantContext
from db.cves import CveMatchRepo
from db.findings import FindingRepo
from db.notifications import NotificationChannelRepo
from db.programs import ProgramRepo
from db.secrets import SecretRepo
from modules.notification import discord
from modules.notification.base import Alert, Senders
from modules.notification.router import passes
from pipelines.notify import run_notify
from tests.fakes import FakeMongo

TENANT = TenantContext("t1", "u1")
AWS_MASKED = "AKIA••••••••LE"


class CaptureHttp:
    def __init__(self, status: int = 204) -> None:
        self.calls: list[tuple[str, dict]] = []
        self.status = status

    async def __call__(self, url: str, payload: dict) -> int:
        self.calls.append((url, payload))
        return self.status


def _senders(status: int = 204) -> tuple[Senders, CaptureHttp]:
    http = CaptureHttp(status)
    return Senders(http=http), http


# -- channel formatting ------------------------------------------------------
async def test_discord_embed_shape_and_color():
    senders, http = _senders()
    alert = Alert(
        title="Exposed .env",
        severity=Severity.CRITICAL,
        program="acme.com",
        location="https://acme.com/.env",
        module="nuclei",
    )
    assert await discord.send(alert, {"webhook_url": "https://d/hook"}, senders) is True
    _, payload = http.calls[0]
    embed = payload["embeds"][0]
    assert "[CRITICAL] Exposed .env" == embed["title"]
    assert embed["color"] == 0xEF4444


async def test_discord_without_url_is_noop():
    senders, http = _senders()
    ok = await discord.send(Alert("x", Severity.HIGH, "p", "l", "m"), {}, senders)
    assert ok is False and http.calls == []


def test_severity_threshold():
    critical = Alert("x", Severity.CRITICAL, "p", "l", "m")
    low = Alert("x", Severity.LOW, "p", "l", "m")
    channel = {"min_severity": "high"}
    assert passes(critical, channel) and not passes(low, channel)


# -- pipeline ----------------------------------------------------------------
async def _seed_channel(mongo, min_sev=Severity.MEDIUM):
    await ProgramRepo.from_mongo(mongo).save(
        Program(tenant_id="t1", program_id="p1", apex_domain="acme.com", verified=True)
    )
    await NotificationChannelRepo.from_mongo(mongo).save(
        NotificationChannel(
            tenant_id="t1",
            channel_id="c1",
            name="ops",
            type=ChannelType.DISCORD,
            min_severity=min_sev,
            config={"webhook_url": "https://d/hook"},
        )
    )


async def test_notify_delivers_and_masks_and_fires_once():
    mongo = FakeMongo()
    await _seed_channel(mongo)
    await FindingRepo(mongo.collection("findings")).upsert(
        Finding(
            tenant_id="t1",
            program_id="p1",
            fingerprint="f1",
            check_id="exposed-env",
            module="nuclei",
            location="https://acme.com/.env",
            name="Exposed .env",
            severity=Severity.CRITICAL,
        )
    )
    await SecretRepo(mongo.collection("secrets")).upsert(
        ExposedSecret(
            tenant_id="t1",
            program_id="p1",
            fingerprint="s1",
            kind="aws_access_key",
            masked=AWS_MASKED,
            value_hash="hash",
            source_locator="https://acme.com/app.js",
            severity=Severity.HIGH,
        )
    )

    senders, http = _senders()
    res = await run_notify(mongo=mongo, tenant=TENANT, program_id="p1", senders=senders)
    assert res["delivered"] == 2

    # the secret alert carries the masked value, never plaintext
    blob = json.dumps(http.calls, ensure_ascii=False)
    assert AWS_MASKED in blob and "AKIAIOSFODNN7EXAMPLE" not in blob

    # alert-once: is_new cleared → second run delivers nothing
    senders2, http2 = _senders()
    res2 = await run_notify(mongo=mongo, tenant=TENANT, program_id="p1", senders=senders2)
    assert res2["delivered"] == 0 and http2.calls == []


async def test_notify_respects_threshold():
    mongo = FakeMongo()
    await _seed_channel(mongo, min_sev=Severity.HIGH)
    await FindingRepo(mongo.collection("findings")).upsert(
        Finding(
            tenant_id="t1",
            program_id="p1",
            fingerprint="f-low",
            check_id="x",
            module="nuclei",
            location="https://acme.com/x",
            name="minor",
            severity=Severity.LOW,
        )
    )
    senders, http = _senders()
    res = await run_notify(mongo=mongo, tenant=TENANT, program_id="p1", senders=senders)
    assert res["delivered"] == 0 and http.calls == []  # low < high threshold


async def test_notify_cve_only_alerts_high_or_kev():
    mongo = FakeMongo()
    await _seed_channel(mongo)
    cves = CveMatchRepo(mongo.collection("cve_matches"))
    await cves.upsert(
        CveMatch(
            tenant_id="t1",
            program_id="p1",
            fingerprint="cve-low",
            cve_id="CVE-1",
            cpe="cpe",
            asset_fingerprint="a",
            confidence="low",
            severity=Severity.MEDIUM,
        )
    )
    await cves.upsert(
        CveMatch(
            tenant_id="t1",
            program_id="p1",
            fingerprint="cve-kev",
            cve_id="CVE-2",
            cpe="cpe",
            asset_fingerprint="a",
            on_kev=True,
            confidence="high",
            severity=Severity.CRITICAL,
        )
    )
    senders, http = _senders()
    res = await run_notify(mongo=mongo, tenant=TENANT, program_id="p1", senders=senders)
    assert res["delivered"] == 1  # only the KEV/high one
    assert "CVE-2" in json.dumps(http.calls) and "CVE-1" not in json.dumps(http.calls)


async def test_notify_no_channels_is_noop_and_keeps_is_new():
    mongo = FakeMongo()
    await ProgramRepo.from_mongo(mongo).save(
        Program(tenant_id="t1", program_id="p1", apex_domain="acme.com", verified=True)
    )
    await FindingRepo(mongo.collection("findings")).upsert(
        Finding(
            tenant_id="t1",
            program_id="p1",
            fingerprint="f1",
            check_id="x",
            module="nuclei",
            location="l",
            name="n",
            severity=Severity.CRITICAL,
        )
    )
    res = await run_notify(mongo=mongo, tenant=TENANT, program_id="p1")
    assert res["delivered"] == 0
    # is_new preserved so it can alert once a channel is added
    doc = await FindingRepo(mongo.collection("findings")).get("t1", "f1")
    assert doc["is_new"] is True
