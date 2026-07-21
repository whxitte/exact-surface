"""Subscription enforcement is server-side and cannot be bypassed from the client.

With licensing enforced, a read-only instance (expired/missing/tampered license) must
refuse every value-generating action — scanning, 403-bypass, adding a domain — with 402,
while reads stay available so the customer never loses visibility of their surface. This
is the guarantee the self-hosted commercial model rests on, so it's pinned here through
the real app (a crafted request via curl/Burp hits the same guard).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from core import entitlements
from core.config import get_settings
from core.license import Entitlements, evaluate
from core.models import Plan
from tests.security.conftest import app_ctx, auth, make_program, signup  # noqa: F401


def _ent(expires_in_days: int) -> Entitlements:
    now = datetime.now(UTC)
    return Entitlements(
        license_id="lic_t",
        customer_id="cus_t",
        customer_name="Test Co",
        plan=Plan.BUSINESS,
        max_domains=25,
        max_users=None,
        features=frozenset(),
        issued_at=now - timedelta(days=30),
        expires_at=now + timedelta(days=expires_in_days),
        grace_days=14,
    )


def _active_state():
    return evaluate(_ent(expires_in_days=10), now=datetime.now(UTC))


def _readonly_state():
    ent = _ent(expires_in_days=-40)  # expired 40d ago, well past 14d grace
    return evaluate(ent, now=datetime.now(UTC))


@pytest.fixture()
def enforced(monkeypatch):
    """Turn on license enforcement for the test; auto-revert setting + cached state."""
    monkeypatch.setattr(get_settings(), "license_enforced", True)
    yield
    entitlements.set_state(None)


def test_readonly_blocks_scanning_but_allows_reads(app_ctx, enforced):  # noqa: F811
    client, _ = app_ctx
    owner = signup(client, email="lic@x.com", name="Lic")["access_token"]
    entitlements.set_state(_active_state())  # active during setup so we can create a program
    pid = make_program(client, owner, "lic.com")

    entitlements.set_state(_readonly_state())  # subscription now lapsed

    # Value-generating actions are refused with 402 …
    assert client.post(f"/programs/{pid}/scan", headers=auth(owner)).status_code == 402
    assert client.post(f"/programs/{pid}/bypass-403", headers=auth(owner)).status_code == 402
    assert (
        client.post("/programs", headers=auth(owner), json={"apex_domain": "extra.com"}).status_code
        == 402
    )
    # … but reads stay available — the customer never loses sight of their surface.
    assert client.get(f"/programs/{pid}/findings", headers=auth(owner)).status_code == 200
    assert client.get(f"/programs/{pid}/assets", headers=auth(owner)).status_code == 200
    assert client.get("/programs", headers=auth(owner)).status_code == 200


def test_active_license_permits_scanning(app_ctx, enforced):  # noqa: F811
    client, _ = app_ctx
    owner = signup(client, email="lic2@x.com", name="Lic2")["access_token"]
    entitlements.set_state(_active_state())
    pid = make_program(client, owner, "lic2.com")
    assert client.post(f"/programs/{pid}/scan", headers=auth(owner)).status_code == 202


def test_me_exposes_license_state(app_ctx, enforced):  # noqa: F811
    client, _ = app_ctx
    owner = signup(client, email="lic3@x.com", name="Lic3")["access_token"]
    entitlements.set_state(_readonly_state())
    me = client.get("/auth/me", headers=auth(owner)).json()
    assert me["license"]["read_only"] is True
    assert me["license"]["status"] == "expired"
    # dedicated endpoint agrees
    lic = client.get("/auth/license", headers=auth(owner)).json()
    assert lic["read_only"] is True


def test_unenforced_is_full_function(app_ctx):  # noqa: F811
    """The default (no license enforced) never gates — dev/self-serve must not 402."""
    client, _ = app_ctx
    owner = signup(client, email="lic4@x.com", name="Lic4")["access_token"]
    pid = make_program(client, owner, "lic4.com")
    assert client.post(f"/programs/{pid}/scan", headers=auth(owner)).status_code == 202
    assert client.get("/auth/me", headers=auth(owner)).json()["license"]["status"] == "unlicensed"
