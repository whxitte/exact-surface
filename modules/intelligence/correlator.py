"""Cross-module correlator (module 27) — chain signals into prioritized issues.

Individual findings are noise; *chains* are signal. An asset that is an exposed
staging env, running a KEV-listed CVE, with an open admin port and a leaked secret
is far more urgent than the sum of four separate rows. This pure function groups
every signal by host, scores the combined risk, and flags multi-signal chains so
the UI and alerts can lead with what actually matters.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit

from core.severity import Severity

_SENSITIVE_PORTS = {21, 22, 23, 445, 1433, 3306, 3389, 5432, 5900, 6379, 9200, 27017}

# Per-signal risk weights (contributions cap at 100).
_SEVERITY_WEIGHT = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 25,
    Severity.MEDIUM: 10,
    Severity.LOW: 4,
    Severity.INFO: 1,
}


@dataclass
class CorrelatedIssue:
    host: str
    risk_score: int
    highest_severity: str
    is_chain: bool
    signals: list[str] = field(default_factory=list)


def _host_of(url_or_host: str) -> str:
    if "://" in url_or_host:
        return (urlsplit(url_or_host).hostname or "").lower()
    return url_or_host.lower().rstrip(".")


def _sev(value) -> Severity:
    try:
        return Severity(value)
    except ValueError:
        return Severity.INFO


def correlate(
    *,
    assets: list[dict],
    findings: list[dict],
    secrets: list[dict],
    leaks: list[dict],
    cve_matches: list[dict],
    ports: list[dict],
) -> list[CorrelatedIssue]:
    """Return per-host correlated issues, highest risk first."""
    ip_to_host = {
        ip: a["hostname"] for a in assets for ip in a.get("resolved_ips", []) if a.get("hostname")
    }
    fp_to_host = {a.get("fingerprint"): a["hostname"] for a in assets if a.get("hostname")}
    ephemeral = {a["hostname"] for a in assets if a.get("is_ephemeral")}

    score: dict[str, int] = {}
    signals: dict[str, list[str]] = {}
    top_sev: dict[str, Severity] = {}
    high_signal_count: dict[str, int] = {}

    def add(host: str, weight: int, label: str, sev: Severity, *, high: bool) -> None:
        if not host:
            return
        score[host] = min(100, score.get(host, 0) + weight)
        signals.setdefault(host, []).append(label)
        if sev.rank > top_sev.get(host, Severity.INFO).rank:
            top_sev[host] = sev
        if high:
            high_signal_count[host] = high_signal_count.get(host, 0) + 1

    for f in findings:
        sev = _sev(f.get("severity"))
        add(
            _host_of(f.get("location", "")),
            _SEVERITY_WEIGHT[sev],
            f"finding:{f.get('check_id', '?')}",
            sev,
            high=sev.rank >= Severity.HIGH.rank,
        )

    for s in secrets:
        add(
            _host_of(s.get("source_locator", "")),
            35,
            f"secret:{s.get('kind', '?')}",
            Severity.HIGH,
            high=True,
        )

    for leak in leaks:
        host = _host_of(leak.get("url") or "")
        add(host or "*", 30, f"leak:{leak.get('kind', '?')}", Severity.HIGH, high=True)

    for m in cve_matches:
        host = fp_to_host.get(m.get("asset_fingerprint"), "")
        on_kev = m.get("on_kev")
        weight = 45 if on_kev else (25 if m.get("confidence") == "high" else 8)
        sev = _sev(m.get("severity"))
        label = f"cve:{m.get('cve_id', '?')}" + (" [KEV]" if on_kev else "")
        add(host, weight, label, sev, high=bool(on_kev) or m.get("confidence") == "high")

    for p in ports:
        if p.get("port") in _SENSITIVE_PORTS:
            host = ip_to_host.get(p.get("ip"), p.get("ip", ""))
            add(host, 15, f"port:{p.get('port')}", Severity.MEDIUM, high=False)

    for host in ephemeral:
        if host in score:  # only boost hosts that already have a signal
            add(host, 10, "ephemeral-env", Severity.LOW, high=False)

    issues = [
        CorrelatedIssue(
            host=host,
            risk_score=score[host],
            highest_severity=top_sev.get(host, Severity.INFO).value,
            is_chain=high_signal_count.get(host, 0) >= 2,
            signals=signals[host],
        )
        for host in score
    ]
    issues.sort(key=lambda i: (i.is_chain, i.risk_score), reverse=True)
    return issues
