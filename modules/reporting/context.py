"""Report data assembly (§module 30-33).

Pure builder that turns the raw per-program documents into one ``ReportContext``
the renderers consume. It sorts findings by severity, keeps only alertable CVE
matches, runs the correlator for the "top risks" section, and carries secrets/leaks
already MASKED (§9c) — a generated report never contains a plaintext secret.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from core.severity import SEVERITIES
from modules.intelligence.correlator import CorrelatedIssue, correlate


def _rank(sev: str) -> int:
    try:
        return SEVERITIES.index(sev)  # type: ignore[arg-type]
    except ValueError:
        return len(SEVERITIES)


@dataclass
class ReportContext:
    program: str
    generated_at: str
    counts: dict
    severity_counts: dict
    findings: list[dict]
    secrets: list[dict]
    leaks: list[dict]
    cve_matches: list[dict]
    issues: list[CorrelatedIssue] = field(default_factory=list)
    #: the build that produced this report, so a report can be traced to a version
    build_id: str = ""

    @property
    def top_issues(self) -> list[CorrelatedIssue]:
        return self.issues[:10]


def _cve_alertable(doc: dict) -> bool:
    return doc.get("confidence") == "high" or bool(doc.get("on_kev"))


def build_report_context(
    *,
    program: str,
    assets: list[dict],
    endpoints: list[dict],
    findings: list[dict],
    secrets: list[dict],
    leaks: list[dict],
    cve_matches: list[dict],
    ports: list[dict],
) -> ReportContext:
    sorted_findings = sorted(findings, key=lambda f: _rank(f.get("severity", "info")))
    severity_counts = {sev: 0 for sev in SEVERITIES}
    for f in sorted_findings:
        sev = f.get("severity", "info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    alertable_cves = [c for c in cve_matches if _cve_alertable(c)]
    issues = correlate(
        assets=assets,
        findings=findings,
        secrets=secrets,
        leaks=leaks,
        cve_matches=cve_matches,
        ports=ports,
    )

    return ReportContext(
        program=program,
        generated_at=datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        counts={
            "assets": len(assets),
            "endpoints": len(endpoints),
            "findings": len(findings),
            "secrets": len(secrets),
            "leaks": len(leaks),
            "cve_matches": len(alertable_cves),
            "open_ports": len(ports),
        },
        severity_counts=severity_counts,
        findings=sorted_findings,
        secrets=secrets,
        leaks=leaks,
        cve_matches=alertable_cves,
        issues=issues,
    )
