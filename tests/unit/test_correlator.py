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
        secrets=[{"kind": "aws_access_key", "source_locator": "https://app.customer.com/main.js"}],
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
