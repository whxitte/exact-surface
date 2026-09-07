from __future__ import annotations

import pytest
from pydantic import ValidationError

from core.lifecycle import FindingState
from core.models import Asset, Authorization, Finding
from core.severity import Severity, escalate_for_kev, from_cvss, meets_threshold
from modules.registry import MODULE_REGISTRY, enabled_modules, required_binaries


# -- models ------------------------------------------------------------------
def test_tenant_id_required_everywhere():
    with pytest.raises(ValidationError):
        Asset(program_id="p1", fingerprint="fp", hostname="h.customer.com")


def test_stateful_defaults():
    a = Asset(tenant_id="t1", program_id="p1", fingerprint="fp", hostname="h.customer.com")
    assert a.is_new is True and a.first_seen <= a.last_seen


def test_finding_defaults_new_and_info():
    f = Finding(
        tenant_id="t1",
        program_id="p1",
        fingerprint="fp",
        check_id="c",
        module="nuclei",
        location="https://h/x",
        name="n",
    )
    assert f.state == FindingState.NEW and f.severity == Severity.INFO


def test_authorization_is_current():
    ok = Authorization(tenant_id="t1", program_id="p1", authorized_by="u1", apex_verified=True)
    revoked = Authorization(
        tenant_id="t1", program_id="p1", authorized_by="u1", apex_verified=True, revoked=True
    )
    unverified = Authorization(tenant_id="t1", program_id="p1", authorized_by="u1")
    assert ok.is_current() and not revoked.is_current() and not unverified.is_current()


# -- severity ----------------------------------------------------------------
@pytest.mark.parametrize(
    "score,band",
    [
        (None, Severity.INFO),
        (0.0, Severity.INFO),
        (3.9, Severity.LOW),
        (5.0, Severity.MEDIUM),
        (7.0, Severity.HIGH),
        (9.8, Severity.CRITICAL),
    ],
)
def test_from_cvss_bands(score, band):
    assert from_cvss(score) == band


def test_kev_escalation_floor_is_high():
    assert escalate_for_kev(Severity.LOW, True) == Severity.HIGH
    assert escalate_for_kev(Severity.CRITICAL, True) == Severity.CRITICAL
    assert escalate_for_kev(Severity.LOW, False) == Severity.LOW


def test_meets_threshold():
    assert meets_threshold(Severity.HIGH, Severity.MEDIUM)
    assert not meets_threshold(Severity.LOW, Severity.HIGH)


# -- registry ----------------------------------------------------------------
def test_masscan_present_but_disabled():
    masscan = next(m for m in MODULE_REGISTRY if m.name == "masscan")
    assert masscan.enabled is False
    assert masscan not in enabled_modules()


def test_required_binaries_exclude_disabled_and_are_sorted():
    bins = required_binaries()
    assert bins == sorted(bins)
    assert "masscan" not in bins  # disabled → not required
    assert {"subfinder", "nuclei", "naabu", "httpx"} <= set(bins)


def test_naabu_is_the_v1_port_scanner():
    naabu = next(m for m in MODULE_REGISTRY if m.name == "naabu")
    assert naabu.enabled and naabu.phase == "2"
