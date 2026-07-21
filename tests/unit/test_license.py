"""The self-hosted licensing core (core.license): sign, verify, and state evaluation.

Pure and offline — an ephemeral keypair is generated per test, so nothing is committed
and the crypto boundary is exercised for real. These pin the security-critical
properties: a tampered or wrong-key token never verifies, and enforcement fails closed
to read-only for every not-active state.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from core.license import (
    Entitlements,
    LicenseError,
    LicenseStatus,
    evaluate,
    generate_keypair,
    sign_license,
    verify_license,
)
from core.models import Plan


def _ent(**over) -> Entitlements:
    now = datetime(2026, 7, 1, tzinfo=UTC)
    base = dict(
        license_id="lic_1",
        customer_id="cus_1",
        customer_name="Acme",
        plan=Plan.BUSINESS,
        max_domains=25,
        max_users=None,
        features=frozenset(),
        issued_at=now,
        expires_at=now + timedelta(days=30),
        grace_days=14,
    )
    base.update(over)
    return Entitlements(**base)


# -- sign / verify roundtrip -------------------------------------------------
def test_sign_and_verify_roundtrip():
    priv, pub = generate_keypair()
    token = sign_license(_ent(), priv)
    ent = verify_license(token, pub)
    assert ent.customer_name == "Acme"
    assert ent.plan is Plan.BUSINESS
    assert ent.max_domains == 25
    assert ent.grace_days == 14


def test_tampered_payload_fails_verification():
    priv, pub = generate_keypair()
    token = sign_license(_ent(max_domains=25), priv)
    prefix, payload, sig = token.split(".")
    # Flip a byte in the payload (attacker tries to raise their domain cap).
    tampered = payload[:-2] + ("AA" if payload[-2:] != "AA" else "BB")
    with pytest.raises(LicenseError):
        verify_license(f"{prefix}.{tampered}.{sig}", pub)


def test_wrong_key_fails_verification():
    priv, _pub = generate_keypair()
    _priv2, pub2 = generate_keypair()  # a different keypair
    token = sign_license(_ent(), priv)
    with pytest.raises(LicenseError):
        verify_license(token, pub2)


@pytest.mark.parametrize("bad", ["", "not-a-token", "vlic1.only-two", "wrongprefix.a.b"])
def test_malformed_tokens_rejected(bad):
    _priv, pub = generate_keypair()
    with pytest.raises(LicenseError):
        verify_license(bad, pub)


# -- state evaluation (fail-closed) ------------------------------------------
def test_active_within_period():
    ent = _ent()
    st = evaluate(ent, now=ent.issued_at + timedelta(days=5))
    assert st.status is LicenseStatus.ACTIVE
    assert st.read_only is False and st.full_function is True


def test_grace_after_expiry_still_full_function():
    ent = _ent()
    st = evaluate(ent, now=ent.expires_at + timedelta(days=3))
    assert st.status is LicenseStatus.GRACE
    assert st.read_only is False  # a late payment must not kill monitoring instantly


def test_expired_past_grace_is_read_only():
    ent = _ent()
    st = evaluate(ent, now=ent.expires_at + timedelta(days=20))
    assert st.status is LicenseStatus.EXPIRED
    assert st.read_only is True and st.full_function is False


def test_missing_license_fails_closed_read_only():
    st = evaluate(None, now=datetime.now(UTC))
    assert st.status is LicenseStatus.MISSING
    assert st.read_only is True


def test_invalid_license_fails_closed_read_only():
    st = evaluate(None, now=datetime.now(UTC), error=LicenseError("bad sig"))
    assert st.status is LicenseStatus.INVALID
    assert st.read_only is True


def test_clock_rollback_is_tampered_read_only():
    ent = _ent()
    # Instance has seen 2026-08-01; clock now claims 2026-06-01 → rolled back.
    floor = datetime(2026, 8, 1, tzinfo=UTC)
    st = evaluate(ent, now=datetime(2026, 6, 1, tzinfo=UTC), clock_floor=floor)
    assert st.status is LicenseStatus.TAMPERED
    assert st.read_only is True


def test_small_clock_skew_is_tolerated():
    ent = _ent()
    floor = ent.issued_at + timedelta(days=5)
    # 1h backward (NTP jitter) is fine; still active.
    st = evaluate(ent, now=floor - timedelta(hours=1), clock_floor=floor)
    assert st.status is LicenseStatus.ACTIVE


def test_enforcement_disabled_is_full_function():
    st = evaluate(None, now=datetime.now(UTC), enforced=False)
    assert st.status is LicenseStatus.UNLICENSED
    assert st.read_only is False and st.full_function is True
