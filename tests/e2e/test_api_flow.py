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
    assert vr.status_code == 200 and vr.json()["token"].startswith("vantari-verify=")
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

    # stats
    st = client.get("/stats", headers=_auth(token)).json()
    assert st["findings"] == 1 and st["findings_by_severity"]["high"] == 1


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
                tenant_id=tenant_id, scan_id="inflight", program_id=pid, pipeline="full",
                status=ScanStatus.RUNNING, started_at=datetime.now(UTC),
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
            ScanRun(tenant_id=tenant_id, scan_id="s1", program_id=pid, pipeline="full",
                    status=ScanStatus.RUNNING)
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
        assert client.get(
            f"/programs/{pid}/scan-runs/nope/logs", headers=_auth(token)
        ).status_code == 404
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
    assert html.status_code == 200 and "Vantari Attack-Surface Report" in html.text
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
    gh = next(i for i in client.get("/integrations", headers=_auth(token)).json()
              if i["name"] == "github_token")
    assert gh["configured"] is True and "ghp_secret123456" not in gh["masked"]

    # unknown key rejected; clear removes it
    bad = client.put("/integrations/nope", headers=_auth(token), json={"value": "x"})
    assert bad.status_code == 404
    assert client.delete("/integrations/github_token", headers=_auth(token)).status_code == 204
    gh = next(i for i in client.get("/integrations", headers=_auth(token)).json()
              if i["name"] == "github_token")
    assert gh["configured"] is False


def test_program_delete_and_monitoring_toggle():
    client, fake, _ = build()
    token = _signup(client)["access_token"]
    pid = client.post("/programs", headers=_auth(token), json={"apex_domain": "acme.com"}).json()[
        "program_id"
    ]

    # monitoring toggle flips Program.enabled
    assert client.post(
        f"/programs/{pid}/monitoring?enabled=false", headers=_auth(token)
    ).status_code == 200
    assert client.get(f"/programs/{pid}", headers=_auth(token)).json()["enabled"] is False
    client.post(f"/programs/{pid}/monitoring?enabled=true", headers=_auth(token))
    assert client.get(f"/programs/{pid}", headers=_auth(token)).json()["enabled"] is True

    # delete removes it entirely → 404 afterwards
    assert client.delete(f"/programs/{pid}", headers=_auth(token)).status_code == 204
    assert client.get(f"/programs/{pid}", headers=_auth(token)).status_code == 404
