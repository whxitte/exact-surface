"""Executive summary (module 33) — CISO-level markdown narrative."""

from __future__ import annotations

from modules.reporting.context import ReportContext


def render_executive_summary(ctx: ReportContext) -> str:
    c = ctx.counts
    sc = ctx.severity_counts
    critical, high = sc.get("critical", 0), sc.get("high", 0)

    posture = "healthy"
    if critical:
        posture = "critical exposure present"
    elif high:
        posture = "elevated risk"
    elif c["findings"]:
        posture = "minor issues"

    lines = [
        f"# Executive Summary — {ctx.program}",
        f"_Generated {ctx.generated_at}_",
        "",
        "## Posture",
        f"External attack-surface posture: **{posture}**. Vantari observed "
        f"{c['assets']} assets, {c['endpoints']} live endpoints, {c['open_ports']} open ports, "
        f"and {c['findings']} findings ({critical} critical, {high} high).",
        "",
    ]

    if ctx.top_issues:
        lines.append("## Top Risks")
        for issue in ctx.top_issues:
            chain = " (attack chain)" if issue.is_chain else ""
            lines.append(
                f"- **{issue.host}** — risk {issue.risk_score}/100{chain}: "
                f"{', '.join(issue.signals[:4])}"
            )
        lines.append("")

    if c["secrets"] or c["leaks"]:
        lines += [
            "## Exposed Credentials",
            f"{c['secrets']} secret(s) exposed on live assets and {c['leaks']} leaked in public "
            "source were detected (values masked). These require **immediate rotation**.",
            "",
        ]

    if c["cve_matches"]:
        lines += [
            "## Known Vulnerabilities",
            f"{c['cve_matches']} high-confidence CVE match(es) against fingerprinted software, "
            "including any CISA-KEV (known-exploited) entries, were identified.",
            "",
        ]

    lines += [
        "## Recommendation",
        "Prioritise remediation of the attack chains above, rotate all exposed credentials, "
        "and patch KEV-listed vulnerabilities first. Vantari will re-verify automatically and "
        "alert on any regression.",
    ]
    return "\n".join(lines)
