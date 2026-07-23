"""The vendor control-plane decisions (control_plane.server) — refresh + update gating.

Pure functions, no server: an ephemeral keypair signs tokens, a temp JSON store holds
subscriptions, and we assert the enforcement — a current subscription renews and gets
updates; a lapsed or suspended one is refused; a forged/unknown token is refused. This
is the logic that keeps a self-hosted subscription actually enforceable.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from control_plane.server import manifest_response, renew
from control_plane.store import LicenseRecord, LicenseStore
from core.license import Entitlements, generate_keypair, sign_license, verify_blob, verify_license
from core.models import Plan

NOW = datetime(2026, 7, 21, tzinfo=UTC)


def _token(priv: str, license_id: str, *, days: int = 30) -> str:
    ent = Entitlements(
        license_id=license_id,
        customer_id="cus_1",
        customer_name="Acme",
        plan=Plan.BUSINESS,
        max_domains=25,
        max_users=None,
        features=frozenset(),
        issued_at=NOW,
        expires_at=NOW + timedelta(days=days),
        grace_days=14,
    )
    return sign_license(ent, priv)


def _renew(store, token, priv, pub):
    return renew(store, token, private_key_pem=priv, public_key_pem=pub, now=NOW)


def _manifest(store, token, manifest, priv, pub):
    return manifest_response(
        store, token, manifest, private_key_pem=priv, public_key_pem=pub, now=NOW
    )


def _store(tmp_path, **records) -> LicenseStore:
    store = LicenseStore(tmp_path / "licenses.json")
    for lid, paid_days, status in records.get("rows", []):
        store.upsert(
            LicenseRecord(
                license_id=lid,
                customer_id="cus_1",
                customer_name="Acme",
                plan="business",
                max_domains=25,
                paid_until=(NOW + timedelta(days=paid_days)).isoformat(),
                status=status,
                grace_days=14,
            )
        )
    return store


def test_current_subscription_renews(tmp_path):
    priv, pub = generate_keypair()
    store = _store(tmp_path, rows=[("lic_ok", 60, "active")])
    code, body = _renew(store, _token(priv, "lic_ok"), priv, pub)
    assert code == 200
    ent = verify_license(body["token"], pub)  # renewed token is validly signed
    assert ent.license_id == "lic_ok"
    assert ent.expires_at <= NOW + timedelta(days=61)  # capped at rolling window


def test_unpaid_subscription_is_declined(tmp_path):
    priv, pub = generate_keypair()
    store = _store(tmp_path, rows=[("lic_late", -5, "active")])  # paid_until in the past
    code, _ = _renew(store, _token(priv, "lic_late"), priv, pub)
    assert code == 402


def test_suspended_subscription_is_declined(tmp_path):
    priv, pub = generate_keypair()
    store = _store(tmp_path, rows=[("lic_susp", 60, "suspended")])
    code, _ = _renew(store, _token(priv, "lic_susp"), priv, pub)
    assert code == 402


def test_unknown_license_is_declined(tmp_path):
    priv, pub = generate_keypair()
    store = _store(tmp_path, rows=[])
    code, _ = _renew(store, _token(priv, "lic_ghost"), priv, pub)
    assert code == 404


def test_forged_token_is_rejected(tmp_path):
    priv, pub = generate_keypair()
    other_priv, _ = generate_keypair()
    store = _store(tmp_path, rows=[("lic_ok", 60, "active")])
    # token signed by a different key → not ours
    code, _ = _renew(store, _token(other_priv, "lic_ok"), priv, pub)
    assert code == 400


def test_update_manifest_signed_for_subscribers(tmp_path):
    priv, pub = generate_keypair()
    store = _store(tmp_path, rows=[("lic_ok", 60, "active")])
    manifest = {"version": "2026.07.21", "sha256": "abc", "templates_url": "https://u/x.tar"}
    tok = _token(priv, "lic_ok")
    code, body = _manifest(store, tok, manifest, priv, pub)
    assert code == 200
    # the client can verify the manifest signature with the public key
    blob = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    assert verify_blob(blob, body["signature"], pub) is True


def test_update_manifest_denied_when_lapsed(tmp_path):
    priv, pub = generate_keypair()
    store = _store(tmp_path, rows=[("lic_late", -1, "active")])
    tok = _token(priv, "lic_late")
    code, _ = _manifest(store, tok, {"version": "1"}, priv, pub)
    assert code == 402
