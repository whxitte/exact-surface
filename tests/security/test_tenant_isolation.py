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


# -- every unscoped query must be justified ----------------------------------

#: Repository methods that deliberately query WITHOUT a tenant_id, each with the
#: reason it is safe. Anything not on this list is a cross-tenant read waiting to
#: happen, so a new one fails this test until somebody writes down why it is allowed.
_UNSCOPED_BY_DESIGN: dict[str, str] = {
    # Pre-authentication: there is no tenant yet. Email is globally unique by design,
    # which is what makes login and the duplicate-signup check possible at all.
    "users.py:get_by_email": "login/signup, before any tenant is known",
    # The id comes from a verified JWT, so the caller has already proven who they are.
    "users.py:get_by_id": "resolves the principal from an authenticated token",
    "users.py:create": "creates the row that will carry the tenant_id",
    "users.py:set_verification": "keyed by user_id from a verified token",
    "users.py:verify_by_token": "the emailed one-time token IS the credential",
    # The key hash is the credential; the tenant is read off the row it returns.
    "apikeys.py:get_by_hash": "the key hash is the credential being presented",
    "apikeys.py:create": "creates the row that will carry the tenant_id",
    # Instance-wide state, not tenant data.
    "license_state.py:get": "instance-wide licence state",
    "license_state.py:bump_clock": "instance-wide clock high-water mark",
    "license_state.py:save_token": "instance-wide licence token",
    "license_state.py:set_applied_update_version": "instance-wide update version",
    "scope_feed.py:get": "shared CDN/cloud ranges, identical for every tenant",
    "scope_feed.py:set": "shared CDN/cloud ranges, identical for every tenant",
    # The scheduler iterates every tenant by definition; it scopes per program after.
    "programs.py:list_all": "the scheduler's cross-tenant sweep, scoped downstream",
}


def test_no_unjustified_cross_tenant_query():
    """Every DB query is tenant-scoped unless it is on the allow-list above.

    Tenant isolation is the one bug in a multi-tenant product that is unrecoverable —
    you cannot un-show a customer somebody else's attack surface. So the default is
    "scoped", and each exception has to be written down and defended rather than
    noticed in review.
    """
    import ast
    import pathlib

    offenders: list[str] = []
    for path in sorted(pathlib.Path("db").glob("*.py")):
        src = path.read_text()
        for node in ast.walk(ast.parse(src)):
            if not isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)):
                continue
            segment = ast.get_source_segment(src, node) or ""
            queries = ("find(", "find_one(", "delete_many(", "update_one(", "update_many(")
            if not any(q in segment for q in queries):
                continue
            if "tenant_id" in segment:
                continue
            key = f"{path.name}:{node.name}"
            if key not in _UNSCOPED_BY_DESIGN:
                offenders.append(key)

    assert not offenders, (
        "these query without a tenant_id and are not on the justified list:\n  "
        + "\n  ".join(offenders)
        + "\n\nAdd a tenant_id filter, or add an entry to _UNSCOPED_BY_DESIGN "
        "explaining why it is safe."
    )


def test_the_justified_list_has_not_gone_stale():
    """An entry for a method that no longer exists hides the fact that nobody has
    re-checked the list."""
    import pathlib

    existing = {
        f"{p.name}:{line.split('def ')[1].split('(')[0].strip()}"
        for p in pathlib.Path("db").glob("*.py")
        for line in p.read_text().splitlines()
        if line.strip().startswith(("def ", "async def "))
    }
    stale = sorted(set(_UNSCOPED_BY_DESIGN) - existing)
    assert not stale, f"justified-list entries for methods that no longer exist: {stale}"
