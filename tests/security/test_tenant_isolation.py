"""Cross-tenant isolation / IDOR (§3.4, §3.7, §8).

Tenant B holds a *valid* JWT for its own tenant. The guarantee under test: with
that valid token, B cannot read or mutate a single one of tenant A's resources
by guessing A's ``program_id`` (or a sub-resource id). Every program-scoped
lookup is scoped to the caller's tenant and must return **404** (not 403 — a 403
would confirm the object exists). Sub-resources whose id is not a program
(notification channels, integrations) must be no-ops across tenants. The same
holds when B authenticates with an API key instead of a JWT, and over the
websocket finding stream.
"""

from __future__ import annotations

import pytest

from core.hashing import finding_fingerprint
from core.models import Asset, CveMatch, Finding, Port, ScanRun, ScanStatus
from db.assets import AssetRepo
from db.audit import ScanRunRepo
from db.cves import CveMatchRepo
from db.findings import FindingRepo
from db.ports import PortRepo
from tests.security.conftest import app_ctx, auth, make_program, run, signup  # noqa: F401

# Every program-scoped GET route. B must get 404 for all of them on A's program.
GET_SUBRESOURCES = [
    "",
    "/findings",
    "/correlation",
    "/attack-surface",
    "/assets",
    "/endpoints",
    "/secrets",
    "/ports",
    "/leaks",
    "/cves",
    "/deltas",
    "/scan-runs",
    "/schedule",
    "/timeouts",
    "/alert-policy",
    "/authorization",
    "/reports",
]


def _seed_tenant_a(fake, tenant_id: str, pid: str) -> None:
    run(
        AssetRepo(fake.collection("assets")).upsert(
            Asset(tenant_id=tenant_id, program_id=pid, fingerprint="a1", hostname="secret.a.com")
        )
    )
    run(
        FindingRepo(fake.collection("findings")).upsert(
            Finding(
                tenant_id=tenant_id,
                program_id=pid,
                fingerprint=finding_fingerprint(pid, "env", "https://a.com/.env"),
                check_id="env",
                module="nuclei",
                location="https://a.com/.env",
                name="A's secret finding",
                severity="critical",
            )
        )
    )
    run(
        CveMatchRepo.from_mongo(fake).upsert(
            CveMatch(
                tenant_id=tenant_id,
                program_id=pid,
                fingerprint="c1",
                cve_id="CVE-2024-9999",
                cpe="cpe:/a:x:y:1.0",
                asset_fingerprint="a1",
                cvss=9.8,
                on_kev=True,
                severity="critical",
            )
        )
    )
    run(
        PortRepo.from_mongo(fake).upsert(
            Port(tenant_id=tenant_id, program_id=pid, fingerprint="p1", ip="45.55.1.1", port=22)
        )
    )
    run(
        ScanRunRepo.from_mongo(fake).save(
            ScanRun(
                tenant_id=tenant_id,
                scan_id="a-scan",
                program_id=pid,
                pipeline="full",
                status=ScanStatus.SUCCESS,
            )
        )
    )


def _two_tenants(client, fake):
    a = signup(client, email="a@corp.com", name="A")
    b = signup(client, email="b@corp.com", name="B")
    a_pid = make_program(client, a["access_token"], "a-corp.com")
    _seed_tenant_a(fake, a["tenant_id"], a_pid)
    return a, b, a_pid


@pytest.mark.parametrize("suffix", GET_SUBRESOURCES)
def test_cross_tenant_get_is_404(app_ctx, suffix):  # noqa: F811
    client, fake = app_ctx
    _a, b, a_pid = _two_tenants(client, fake)
    r = client.get(f"/programs/{a_pid}{suffix}", headers=auth(b["access_token"]))
    assert r.status_code == 404, f"IDOR: B reached A's /programs/{{id}}{suffix} → {r.status_code}"


def test_cross_tenant_scan_run_logs_is_404(app_ctx):  # noqa: F811
    client, fake = app_ctx
    _a, b, a_pid = _two_tenants(client, fake)
    r = client.get(f"/programs/{a_pid}/scan-runs/a-scan/logs", headers=auth(b["access_token"]))
    assert r.status_code == 404


def test_cross_tenant_mutations_are_404(app_ctx):  # noqa: F811
    """Destructive/mutating routes are equally locked: delete, scan, monitoring, config."""
    client, fake = app_ctx
    _a, b, a_pid = _two_tenants(client, fake)
    bh = auth(b["access_token"])
    assert client.delete(f"/programs/{a_pid}", headers=bh).status_code == 404
    assert client.post(f"/programs/{a_pid}/scan", headers=bh).status_code == 404
    assert client.post(f"/programs/{a_pid}/monitoring?enabled=false", headers=bh).status_code == 404
    assert client.post(f"/programs/{a_pid}/authorization", headers=bh, json={}).status_code == 404
    assert (
        client.post(f"/programs/{a_pid}/alert-policy", headers=bh, json={"policy": {}}).status_code
        == 404
    )
    assert (
        client.post(f"/programs/{a_pid}/verify/request?method=dns_txt", headers=bh).status_code
        == 404
    )


def test_a_data_still_intact_after_b_attempts(app_ctx):  # noqa: F811
    """B's probing left A's data untouched and A can still read its own finding."""
    client, fake = app_ctx
    a, b, a_pid = _two_tenants(client, fake)
    client.delete(f"/programs/{a_pid}", headers=auth(b["access_token"]))  # should be a no-op (404)
    findings = client.get(f"/programs/{a_pid}/findings", headers=auth(a["access_token"])).json()
    assert any(f["name"] == "A's secret finding" for f in findings)


def test_api_key_cannot_cross_tenant(app_ctx):  # noqa: F811
    """An API key issued to tenant B is as tenant-locked as B's JWT."""
    client, fake = app_ctx
    a, b, a_pid = _two_tenants(client, fake)
    raw = client.post(
        "/auth/api-keys", headers=auth(b["access_token"]), json={"name": "ci"}
    ).json()["api_key"]
    r = client.get(f"/programs/{a_pid}/findings", headers={"X-API-Key": raw})
    assert r.status_code == 404


def test_notification_channel_delete_is_tenant_scoped(app_ctx):  # noqa: F811
    """B guessing A's channel_id deletes nothing of A's."""
    client, fake = app_ctx
    a = signup(client, email="na@x.com", name="NA")
    b = signup(client, email="nb@x.com", name="NB")
    created = client.post(
        "/notifications",
        headers=auth(a["access_token"]),
        json={"name": "ops", "type": "discord", "config": {"webhook_url": "https://d/h"}},
    )
    a_cid = created.json()["channel_id"]
    # B tries to delete A's channel by id — succeeds as a no-op, A keeps it
    client.delete(f"/notifications/{a_cid}", headers=auth(b["access_token"]))
    a_channels = client.get("/notifications", headers=auth(a["access_token"])).json()
    assert any(c["channel_id"] == a_cid for c in a_channels)


def test_websocket_stream_only_sees_own_tenant(app_ctx):  # noqa: F811
    """A's findings never appear in B's websocket snapshot."""
    client, fake = app_ctx
    a, b, a_pid = _two_tenants(client, fake)
    with client.websocket_connect(f"/ws/findings?token={b['access_token']}") as ws:
        msg = ws.receive_json()
        assert msg["type"] == "snapshot"
        assert all(f["name"] != "A's secret finding" for f in msg["new_findings"])
