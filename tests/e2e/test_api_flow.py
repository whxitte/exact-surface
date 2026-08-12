"""End-to-end API tests: the self-serve workflow + tenant isolation (§8, Phase C exit).

Sync tests using FastAPI TestClient. Mongo is a FakeMongo injected via dependency
override; the domain verifier is a stub so no real DNS/HTTP happens.
"""

from __future__ import annotations

import asyncio

from fastapi.testclient import TestClient

from api.deps import get_domain_verifier, get_mongo_dep
from api.main import create_app
from core.hashing import finding_fingerprint
from core.models import Finding
from db.findings import FindingRepo
from tests.fakes import FakeMongo


class StubVerifier:
    def __init__(self, result: bool = True) -> None:
        self.result = result

    async def verify(self, apex, method, token):  # noqa: ANN001
        return self.result


def build():
    fake = FakeMongo()
    verifier = StubVerifier(result=True)
    app = create_app()
    app.dependency_overrides[get_mongo_dep] = lambda: fake
    app.dependency_overrides[get_domain_verifier] = lambda: verifier
    return TestClient(app), fake, verifier


def _run(coro):
    return asyncio.run(coro)


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def _signup(client, email="owner@acme.com", pw="supersecret1", name="Acme"):
    r = client.post("/auth/signup", json={"email": email, "password": pw, "tenant_name": name})
    assert r.status_code == 201, r.text
    return r.json()


def test_full_self_serve_workflow():
    client, fake, _ = build()

    # signup → token
    tok = _signup(client)
    token, tenant_id = tok["access_token"], tok["tenant_id"]

    # me
    me = client.get("/auth/me", headers=_auth(token)).json()
    assert me["tenant_id"] == tenant_id and me["role"] == "owner"

    # create program
    prog = client.post("/programs", headers=_auth(token), json={"apex_domain": "Acme.com"}).json()
    pid = prog["program_id"]
    assert prog["apex_domain"] == "acme.com" and prog["verified"] is False

    # request + check verification (stub says True)
    vr = client.post(f"/programs/{pid}/verify/request?method=dns_txt", headers=_auth(token))
    assert vr.status_code == 200 and vr.json()["token"].startswith("exactsurface-verify=")
    vc = client.post(f"/programs/{pid}/verify/check", headers=_auth(token))
    assert vc.json()["verified"] is True
    assert client.get(f"/programs/{pid}", headers=_auth(token)).json()["verified"] is True

    # authorization
    az = client.post(f"/programs/{pid}/authorization", headers=_auth(token), json={})
    assert az.status_code == 201 and az.json()["apex_verified"] is True

    # scan trigger now allowed
    assert client.post(f"/programs/{pid}/scan", headers=_auth(token)).status_code == 202

    # seed a finding, read it back
    _run(
        FindingRepo(fake.collection("findings")).upsert(
            Finding(
                tenant_id=tenant_id,
                program_id=pid,
                fingerprint=finding_fingerprint(pid, "exposed-env", "https://acme.com/.env"),
                check_id="exposed-env",
                module="nuclei",
                location="https://acme.com/.env",
                name="Exposed .env",
                severity="high",
            )
        )
    )
    findings = client.get(f"/programs/{pid}/findings", headers=_auth(token)).json()
    assert len(findings) == 1 and findings[0]["name"] == "Exposed .env"

    # stats — incl. the signal-quality fields the overview binds to
    st = client.get("/stats", headers=_auth(token)).json()
    assert st["findings"] == 1 and st["findings_by_severity"]["high"] == 1
    assert st["open_actionable"] == 1  # the one high finding is actionable
    assert st["informational"] == 0
    assert st["false_positive_rate"] is None  # nothing triaged/decided yet
    assert st["decided"] == 0


def test_scan_refused_without_verification_and_authorization():
    client, _, _ = build()
    token = _signup(client)["access_token"]
    pid = client.post("/programs", headers=_auth(token), json={"apex_domain": "acme.com"}).json()[
        "program_id"
    ]
    # not verified → 409
    assert client.post(f"/programs/{pid}/scan", headers=_auth(token)).status_code == 409
    # verify but no authorization yet → still 409
    client.post(f"/programs/{pid}/verify/request?method=dns_txt", headers=_auth(token))
    client.post(f"/programs/{pid}/verify/check", headers=_auth(token))
    assert client.post(f"/programs/{pid}/scan", headers=_auth(token)).status_code == 409


def test_scan_refused_while_one_already_running():
    """A second scan is blocked at the API (not just the UI) while one is in flight."""
    from datetime import UTC, datetime

    from core.models import ScanRun, ScanStatus
    from db.audit import ScanRunRepo

    client, fake, _ = build()
    tok = _signup(client)
    token, tenant_id = tok["access_token"], tok["tenant_id"]
    pid = client.post("/programs", headers=_auth(token), json={"apex_domain": "acme.com"}).json()[
        "program_id"
    ]
    client.post(f"/programs/{pid}/verify/request?method=dns_txt", headers=_auth(token))
    client.post(f"/programs/{pid}/verify/check", headers=_auth(token))
    client.post(f"/programs/{pid}/authorization", headers=_auth(token), json={})

    # Seed an in-flight full run for this program.
    _run(
        ScanRunRepo(fake.collection("scan_runs")).save(
            ScanRun(
                tenant_id=tenant_id,
                scan_id="inflight",
                program_id=pid,
                pipeline="full",
                status=ScanStatus.RUNNING,
                started_at=datetime.now(UTC),
            )
        )
    )
    r = client.post(f"/programs/{pid}/scan", headers=_auth(token))
    assert r.status_code == 409 and "already running" in r.json()["detail"]


def test_scan_run_logs_endpoint_tenant_scoped():
    from core import activity_bus
    from core.models import ScanRun, ScanStatus
    from db.audit import ScanRunRepo

    client, fake, _ = build()
    tok = _signup(client)
    token, tenant_id = tok["access_token"], tok["tenant_id"]
    pid = client.post("/programs", headers=_auth(token), json={"apex_domain": "acme.com"}).json()[
        "program_id"
    ]
    _run(
        ScanRunRepo(fake.collection("scan_runs")).save(
            ScanRun(
                tenant_id=tenant_id,
                scan_id="s1",
                program_id=pid,
                pipeline="full",
                status=ScanStatus.RUNNING,
            )
        )
    )

    class FakeBus:
        async def get_logs(self, scan_id, limit=500):
            return ["13:20:18 INFO    [crawl] katana crawling acme.com"]

    activity_bus.set_bus(FakeBus())
    try:
        r = client.get(f"/programs/{pid}/scan-runs/s1/logs", headers=_auth(token))
        assert r.status_code == 200
        assert r.json()["lines"] == ["13:20:18 INFO    [crawl] katana crawling acme.com"]
        # a scan id that isn't this program's run → 404 (can't read another's logs)
        assert (
            client.get(f"/programs/{pid}/scan-runs/nope/logs", headers=_auth(token)).status_code
            == 404
        )
    finally:
        activity_bus.set_bus(None)


def test_verify_check_before_request_is_400():
    client, _, _ = build()
    token = _signup(client)["access_token"]
    pid = client.post("/programs", headers=_auth(token), json={"apex_domain": "acme.com"}).json()[
        "program_id"
    ]
    assert client.post(f"/programs/{pid}/verify/check", headers=_auth(token)).status_code == 400


def test_tenant_isolation():
    client, _, _ = build()
    a = _signup(client, email="a@a.com", name="A")
    b = _signup(client, email="b@b.com", name="B")
    a_pid = client.post(
        "/programs", headers=_auth(a["access_token"]), json={"apex_domain": "a-corp.com"}
    ).json()["program_id"]

    # B cannot see A's program (scoped lookup → 404, not 403 that would confirm existence)
    assert client.get(f"/programs/{a_pid}", headers=_auth(b["access_token"])).status_code == 404
    assert (
        client.get(f"/programs/{a_pid}/findings", headers=_auth(b["access_token"])).status_code
        == 404
    )
    # B's program list is empty
    assert client.get("/programs", headers=_auth(b["access_token"])).json() == []


def test_auth_required_and_bad_token():
    client, _, _ = build()
    assert client.get("/programs").status_code == 401
    assert client.get("/auth/me", headers=_auth("garbage.token.here")).status_code == 401


def test_duplicate_email_rejected():
    client, _, _ = build()
    _signup(client, email="dup@x.com")
    r = client.post(
        "/auth/signup", json={"email": "dup@x.com", "password": "supersecret1", "tenant_name": "X2"}
    )
    assert r.status_code == 409


def test_login_flow_and_wrong_password():
    client, _, _ = build()
    _signup(client, email="login@x.com", pw="rightpassword1", name="L")
    ok = client.post("/auth/login", json={"email": "login@x.com", "password": "rightpassword1"})
    assert ok.status_code == 200 and ok.json()["access_token"]
    bad = client.post("/auth/login", json={"email": "login@x.com", "password": "wrongpassword"})
    assert bad.status_code == 401


def test_api_key_issuance_and_use():
    client, _, _ = build()
    token = _signup(client, email="key@x.com")["access_token"]
    created = client.post("/auth/api-keys", headers=_auth(token), json={"name": "ci"})
    assert created.status_code == 201
    raw = created.json()["api_key"]
    assert raw.startswith("vnt_")
    # use the API key instead of the JWT
    me = client.get("/auth/me", headers={"X-API-Key": raw})
    assert me.status_code == 200 and me.json()["auth"] == "apikey"


def test_notification_channel_crud():
    client, _, _ = build()
    token = _signup(client, email="notif@x.com")["access_token"]
    # create a Discord channel
    created = client.post(
        "/notifications",
        headers=_auth(token),
        json={
            "name": "ops",
            "type": "discord",
            "min_severity": "high",
            "config": {"webhook_url": "https://discord/hook"},
        },
    )
    assert created.status_code == 201
    cid = created.json()["channel_id"]
    # list shows it
    listed = client.get("/notifications", headers=_auth(token)).json()
    assert len(listed) == 1 and listed[0]["type"] == "discord"
    # delete it
    assert client.delete(f"/notifications/{cid}", headers=_auth(token)).status_code == 204
    assert client.get("/notifications", headers=_auth(token)).json() == []


def test_report_download():
    client, fake, _ = build()
    tok = _signup(client, email="report@x.com")
    token, tenant_id = tok["access_token"], tok["tenant_id"]
    pid = client.post("/programs", headers=_auth(token), json={"apex_domain": "rep.com"}).json()[
        "program_id"
    ]
    _run(
        FindingRepo(fake.collection("findings")).upsert(
            Finding(
                tenant_id=tenant_id,
                program_id=pid,
                fingerprint=finding_fingerprint(pid, "exposed-env", "https://rep.com/.env"),
                check_id="exposed-env",
                module="nuclei",
                location="https://rep.com/.env",
                name="Exposed .env",
                severity="critical",
            )
        )
    )
    # HackerOne markdown
    h1 = client.get(f"/programs/{pid}/reports?format=hackerone", headers=_auth(token))
    assert h1.status_code == 200 and "text/markdown" in h1.headers["content-type"]
    assert "## [CRITICAL] Exposed .env" in h1.text
    assert "attachment" in h1.headers["content-disposition"]
    # HTML
    html = client.get(f"/programs/{pid}/reports?format=html", headers=_auth(token))
    assert html.status_code == 200 and "ExactSurface Attack-Surface Report" in html.text
    # unknown format → 400
    assert (
        client.get(f"/programs/{pid}/reports?format=xlsx", headers=_auth(token)).status_code == 400
    )


def test_websocket_finding_snapshot():
    client, fake, _ = build()
    tok = _signup(client, email="ws@x.com")
    token, tenant_id = tok["access_token"], tok["tenant_id"]
    pid = client.post("/programs", headers=_auth(token), json={"apex_domain": "ws.com"}).json()[
        "program_id"
    ]
    _run(
        FindingRepo(fake.collection("findings")).upsert(
            Finding(
                tenant_id=tenant_id,
                program_id=pid,
                fingerprint=finding_fingerprint(pid, "c", "https://ws.com/x"),
                check_id="c",
                module="nuclei",
                location="https://ws.com/x",
                name="Live finding",
                severity="critical",
            )
        )
    )
    with client.websocket_connect(f"/ws/findings?token={token}") as ws:
        msg = ws.receive_json()
        assert msg["type"] == "snapshot"
        assert any(f["name"] == "Live finding" for f in msg["new_findings"])


def test_integrations_set_list_and_clear():
    client, _, _ = build()
    token = _signup(client)["access_token"]

    # listed but unconfigured out of the box
    items = client.get("/integrations", headers=_auth(token)).json()
    gh = next(i for i in items if i["name"] == "github_token")
    assert gh["configured"] is False and gh["label"]

    # set it → 204, then it reads back configured + masked (never the plaintext)
    r = client.put(
        "/integrations/github_token", headers=_auth(token), json={"value": "ghp_secret123456"}
    )
    assert r.status_code == 204
    gh = next(
        i
        for i in client.get("/integrations", headers=_auth(token)).json()
        if i["name"] == "github_token"
    )
    assert gh["configured"] is True and "ghp_secret123456" not in gh["masked"]

    # unknown key rejected; clear removes it
    bad = client.put("/integrations/nope", headers=_auth(token), json={"value": "x"})
    assert bad.status_code == 404
    assert client.delete("/integrations/github_token", headers=_auth(token)).status_code == 204
    gh = next(
        i
        for i in client.get("/integrations", headers=_auth(token)).json()
        if i["name"] == "github_token"
    )
    assert gh["configured"] is False


def test_program_delete_and_monitoring_toggle():
    client, fake, _ = build()
    token = _signup(client)["access_token"]
    pid = client.post("/programs", headers=_auth(token), json={"apex_domain": "acme.com"}).json()[
        "program_id"
    ]

    # monitoring toggle flips Program.enabled
    assert (
        client.post(f"/programs/{pid}/monitoring?enabled=false", headers=_auth(token)).status_code
        == 200
    )
    assert client.get(f"/programs/{pid}", headers=_auth(token)).json()["enabled"] is False
    client.post(f"/programs/{pid}/monitoring?enabled=true", headers=_auth(token))
    assert client.get(f"/programs/{pid}", headers=_auth(token)).json()["enabled"] is True

    # delete removes it entirely → 404 afterwards
    assert client.delete(f"/programs/{pid}", headers=_auth(token)).status_code == 204
    assert client.get(f"/programs/{pid}", headers=_auth(token)).status_code == 404


def _set_plan(fake, tenant_id: str, plan: str) -> None:
    """Set a tenant's stored plan, as an operator would."""
    import asyncio

    asyncio.run(
        fake.collection("tenants").update_one({"tenant_id": tenant_id}, {"$set": {"plan": plan}})
    )


def test_schedule_endpoints_program_and_tenant_defaults():
    client, fake, _ = build()
    signed = _signup(client)
    token = signed["access_token"]
    # Test schedule overrides precedence.
    _set_plan(fake, signed["tenant_id"], "business")
    pid = client.post("/programs", headers=_auth(token), json={"apex_domain": "acme.com"}).json()[
        "program_id"
    ]

    # program schedule: every configurable phase present with a next-due breakdown
    sch = client.get(f"/programs/{pid}/schedule", headers=_auth(token)).json()
    phases = {p["pipeline"]: p for p in sch["phases"]}
    assert "ingest" in phases and phases["ingest"]["source"] == "default"
    assert sch["last_full_run"] is None  # never scanned yet

    # tenant default: slow ingest to 12h → program inherits it as source "tenant"
    client.post("/schedule/defaults", headers=_auth(token), json={"overrides": {"ingest": 43200}})
    phases = {
        p["pipeline"]: p
        for p in client.get(f"/programs/{pid}/schedule", headers=_auth(token)).json()["phases"]
    }
    assert phases["ingest"]["interval_seconds"] == 43200 and phases["ingest"]["source"] == "tenant"

    # program override wins over the tenant default; sub-floor values are clamped
    client.post(
        f"/programs/{pid}/schedule", headers=_auth(token), json={"overrides": {"ingest": 5}}
    )
    phases = {
        p["pipeline"]: p
        for p in client.get(f"/programs/{pid}/schedule", headers=_auth(token)).json()["phases"]
    }
    assert phases["ingest"]["source"] == "program"
    assert phases["ingest"]["interval_seconds"] == 3600  # floored to the Business plan's 1h


def test_timeout_config_program_and_tenant_defaults():
    client, _, _ = build()
    token = _signup(client)["access_token"]
    pid = client.post("/programs", headers=_auth(token), json={"apex_domain": "acme.com"}).json()[
        "program_id"
    ]

    # program timeouts: every stage present, scan defaults to 3600s from built-ins
    stages = {
        s["stage"]: s
        for s in client.get(f"/programs/{pid}/timeouts", headers=_auth(token)).json()["stages"]
    }
    assert stages["scan"]["timeout_seconds"] == 3600 and stages["scan"]["source"] == "default"

    # tenant default lowers scan to 30m → program inherits it (source "tenant")
    client.post(
        "/schedule/timeout-defaults", headers=_auth(token), json={"overrides": {"scan": 1800}}
    )
    stages = {
        s["stage"]: s
        for s in client.get(f"/programs/{pid}/timeouts", headers=_auth(token)).json()["stages"]
    }
    assert stages["scan"]["timeout_seconds"] == 1800 and stages["scan"]["source"] == "tenant"

    # program override wins; absurd values are clamped to MAX
    client.post(
        f"/programs/{pid}/timeouts", headers=_auth(token), json={"overrides": {"scan": 999999999}}
    )
    stages = {
        s["stage"]: s
        for s in client.get(f"/programs/{pid}/timeouts", headers=_auth(token)).json()["stages"]
    }
    assert stages["scan"]["source"] == "program" and stages["scan"]["timeout_seconds"] == 6 * 3600


def test_attack_surface_endpoint_shape():
    from core.models import Asset
    from db.assets import AssetRepo

    client, fake, _ = build()
    tok = _signup(client)
    token, tenant_id = tok["access_token"], tok["tenant_id"]
    pid = client.post("/programs", headers=_auth(token), json={"apex_domain": "acme.com"}).json()[
        "program_id"
    ]
    _run(
        AssetRepo(fake.collection("assets")).upsert(
            Asset(tenant_id=tenant_id, program_id=pid, fingerprint="a1", hostname="a.acme.com")
        )
    )
    surf = client.get(f"/programs/{pid}/attack-surface", headers=_auth(token)).json()
    assert surf["current"]["assets"]["total"] == 1 and surf["current"]["total"] == 1
    assert "series" in surf and "recent" in surf
    assert surf["change"]["assets"]["opened"] == 1  # brand-new asset, no scans yet


def test_cves_and_correlation_endpoints():
    from core.models import Asset, CveMatch, Finding
    from db.assets import AssetRepo
    from db.cves import CveMatchRepo

    client, fake, _ = build()
    tok = _signup(client)
    token, tenant_id = tok["access_token"], tok["tenant_id"]
    pid = client.post("/programs", headers=_auth(token), json={"apex_domain": "acme.com"}).json()[
        "program_id"
    ]
    _run(
        AssetRepo(fake.collection("assets")).upsert(
            Asset(tenant_id=tenant_id, program_id=pid, fingerprint="a1", hostname="app.acme.com")
        )
    )
    _run(
        CveMatchRepo.from_mongo(fake).upsert(
            CveMatch(
                tenant_id=tenant_id,
                program_id=pid,
                fingerprint="c1",
                cve_id="CVE-2024-0001",
                cpe="cpe:/a:nginx:nginx:1.0",
                asset_fingerprint="a1",
                cvss=9.8,
                on_kev=True,
                severity="critical",
            )
        )
    )
    _run(
        FindingRepo(fake.collection("findings")).upsert(
            Finding(
                tenant_id=tenant_id,
                program_id=pid,
                fingerprint=finding_fingerprint(pid, "x", "app.acme.com"),
                check_id="x",
                module="nuclei",
                location="app.acme.com",
                name="Something",
                severity="high",
            )
        )
    )

    cves = client.get(f"/programs/{pid}/cves", headers=_auth(token)).json()
    assert len(cves) == 1 and cves[0]["cve_id"] == "CVE-2024-0001" and cves[0]["on_kev"] is True

    corr = client.get(f"/programs/{pid}/correlation", headers=_auth(token)).json()
    assert corr["count"] >= 1
    hosts = {i["host"]: i for i in corr["issues"]}
    assert "app.acme.com" in hosts and hosts["app.acme.com"]["risk_score"] > 0


def test_ports_reader_flags_gone():
    import datetime as _dt

    from core.models import Port, ScanRun, ScanStatus
    from db.audit import ScanRunRepo
    from db.ports import PortRepo

    client, fake, _ = build()
    tok = _signup(client)
    token, tenant_id = tok["access_token"], tok["tenant_id"]
    pid = client.post("/programs", headers=_auth(token), json={"apex_domain": "acme.com"}).json()[
        "program_id"
    ]
    t0 = _dt.datetime(2026, 7, 1, tzinfo=_dt.UTC)
    t2 = t0 + _dt.timedelta(days=1)
    repo = PortRepo.from_mongo(fake)
    _run(
        repo.upsert(
            Port(tenant_id=tenant_id, program_id=pid, fingerprint="live", ip="1.1.1.1", port=443)
        )
    )
    _run(
        repo.upsert(
            Port(tenant_id=tenant_id, program_id=pid, fingerprint="old", ip="2.2.2.2", port=22)
        )
    )
    # 'live' re-seen at the latest full-coverage port scan (t2); 'old' not seen since t0.
    _run(fake.collection("ports").update_one({"fingerprint": "live"}, {"$set": {"last_seen": t2}}))
    _run(fake.collection("ports").update_one({"fingerprint": "old"}, {"$set": {"last_seen": t0}}))
    # two full-coverage port_scan runs — the newer (t2) is the gone reference.
    for sid, start in [("r0", t0), ("r2", t2)]:
        _run(
            ScanRunRepo.from_mongo(fake).save(
                ScanRun(
                    tenant_id=tenant_id,
                    scan_id=sid,
                    program_id=pid,
                    pipeline="port_scan",
                    status=ScanStatus.SUCCESS,
                    started_at=start,
                )
            )
        )
    ports = {
        p["fingerprint"]: p
        for p in client.get(f"/programs/{pid}/ports", headers=_auth(token)).json()
    }
    assert ports["live"]["gone"] is False and ports["old"]["gone"] is True


def test_alert_policy_endpoints():
    client, _, _ = build()
    tok = _signup(client)
    token = tok["access_token"]
    pid = client.post("/programs", headers=_auth(token), json={"apex_domain": "acme.com"}).json()[
        "program_id"
    ]

    # defaults present out of the box
    got = client.get(f"/programs/{pid}/alert-policy", headers=_auth(token)).json()
    assert got["alert_policy"] == {}  # no overrides yet
    assert got["effective"]["finding_min_severity"] == "medium"
    assert "critical" in got["severities"]

    # set an override; the port filter is normalised server-side
    saved = client.post(
        f"/programs/{pid}/alert-policy",
        headers=_auth(token),
        json={"policy": {"finding_min_severity": "high", "port_filter": "22, 80,x,1-100"}},
    ).json()
    assert saved["alert_policy"]["finding_min_severity"] == "high"
    assert saved["alert_policy"]["port_filter"] == "22,80,1-100"
    assert saved["effective"]["finding_min_severity"] == "high"

    # account-wide defaults round-trip too
    client.post(
        "/schedule/alert-policy", headers=_auth(token), json={"policy": {"alert_leaks": False}}
    )
    defs = client.get("/schedule/alert-policy", headers=_auth(token)).json()
    assert defs["alert_policy"]["alert_leaks"] is False
