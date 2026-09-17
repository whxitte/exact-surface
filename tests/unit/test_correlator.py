"""Cross-module correlation — chains beat isolated findings."""

from __future__ import annotations

from core.hashing import asset_fingerprint
from modules.intelligence.correlator import correlate

APP_FP = asset_fingerprint("p1", "app.customer.com")

ASSETS = [
    {
        "hostname": "app.customer.com",
        "fingerprint": APP_FP,
        "resolved_ips": ["45.55.1.1"],
        "is_ephemeral": False,
    },
    {
        "hostname": "staging.customer.com",
        "fingerprint": asset_fingerprint("p1", "staging.customer.com"),
        "resolved_ips": ["45.55.1.2"],
        "is_ephemeral": True,
    },
]


def test_chain_ranks_above_isolated_finding():
    issues = correlate(
        assets=ASSETS,
        findings=[
            {
                "check_id": "exposed-env",
                "location": "https://app.customer.com/.env",
                "severity": "critical",
            },
            {
                "check_id": "minor",
                "location": "https://staging.customer.com/",
                "severity": "medium",
            },
        ],
        secrets=[
            {
                "kind": "aws_access_key",
                "source_locator": "https://app.customer.com/main.js",
                "severity": "critical",
            }
        ],
        leaks=[],
        cve_matches=[
            {
                "cve_id": "CVE-2020-1",
                "asset_fingerprint": APP_FP,
                "on_kev": True,
                "confidence": "high",
                "severity": "critical",
            }
        ],
        ports=[{"ip": "45.55.1.1", "port": 22}],
    )
    top = issues[0]
    assert top.host == "app.customer.com"
    assert top.is_chain is True  # critical finding + secret + KEV cve = multi-signal
    assert top.risk_score == 100  # capped
    assert any("KEV" in s for s in top.signals)
    assert any(s.startswith("secret:") for s in top.signals)
    assert any(s.startswith("port:22") for s in top.signals)
    # staging present but lower priority and not a chain
    staging = next(i for i in issues if i.host == "staging.customer.com")
    assert staging.is_chain is False and staging.risk_score < top.risk_score


def test_cve_mapped_by_fingerprint_and_port_by_ip():
    issues = correlate(
        assets=ASSETS,
        findings=[],
        secrets=[],
        leaks=[],
        cve_matches=[
            {
                "cve_id": "CVE-x",
                "asset_fingerprint": APP_FP,
                "on_kev": False,
                "confidence": "high",
                "severity": "high",
            }
        ],
        ports=[{"ip": "45.55.1.1", "port": 3389}],
    )
    hosts = {i.host for i in issues}
    assert hosts == {"app.customer.com"}  # both signals resolved to the same host


def test_empty_inputs_yield_no_issues():
    assert correlate(assets=[], findings=[], secrets=[], leaks=[], cve_matches=[], ports=[]) == []


def test_external_host_is_never_a_correlated_asset():
    """A dork result URL or hijackable link points at an external host we do not own.
    It must not rank as this program's host — even at critical severity."""
    issues = correlate(
        assets=ASSETS,
        findings=[
            {"check_id": "dork", "location": "https://github.com/x/y", "severity": "critical"},
            {"check_id": "env", "location": "https://app.customer.com/.env", "severity": "high"},
        ],
        secrets=[],
        leaks=[],
        cve_matches=[],
        ports=[],
    )
    hosts = {i.host for i in issues}
    assert "github.com" not in hosts
    assert hosts == {"app.customer.com"}


def test_suppressed_findings_are_not_signals():
    """A finding a re-check retired (FALSE_POSITIVE) or that was fixed (RESOLVED) is
    not a live signal — it must not contribute to a host's risk or chain."""
    issues = correlate(
        assets=ASSETS,
        findings=[
            {
                "check_id": "old",
                "location": "https://app.customer.com/x",
                "severity": "critical",
                "state": "false_positive",
            },
            {
                "check_id": "fixed",
                "location": "https://app.customer.com/y",
                "severity": "critical",
                "state": "resolved",
            },
        ],
        secrets=[],
        leaks=[],
        cve_matches=[],
        ports=[],
    )
    assert issues == []  # both findings suppressed → no host has any live signal


def test_info_secret_is_not_a_high_signal():
    """A public-by-design secret (e.g. a Firebase web key classified INFO) must not
    rate its host high or count toward a chain — it carries its own severity, not a
    hardcoded HIGH."""
    issues = correlate(
        assets=ASSETS,
        findings=[],
        secrets=[
            {
                "kind": "google_api_key",
                "source_locator": "https://app.customer.com/init.json",
                "severity": "info",
            }
        ],
        leaks=[],
        cve_matches=[],
        ports=[],
    )
    top = next(i for i in issues if i.host == "app.customer.com")
    assert top.highest_severity == "info"
    assert top.is_chain is False
    assert top.risk_score == 1  # INFO weight, not the old flat 35
