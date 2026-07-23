"""HackerOne-format markdown report (module 32).

One submission-ready section per finding: title, asset, description, reproduction,
severity-based impact, and references — the shape a bug-bounty triager expects.
"""

from __future__ import annotations

from modules.reporting.context import ReportContext

_IMPACT = {
    "critical": "Full compromise or direct exposure of sensitive data is possible.",
    "high": "An attacker can obtain significant unauthorized access or data.",
    "medium": "Meaningful information disclosure or a foothold for further attack.",
    "low": "Limited information disclosure or hardening gap.",
    "info": "Informational; no direct security impact.",
}


def _reproduction(finding: dict) -> str:
    if finding.get("reproduction"):
        return finding["reproduction"]
    return f"```\ncurl -i {finding.get('location', '')}\n```"


def render_hackerone(ctx: ReportContext) -> str:
    lines = [
        f"# ExactSurface Findings — {ctx.program}",
        f"_Generated {ctx.generated_at} · detection only, no exploitation._",
        "",
    ]
    if not ctx.findings:
        lines.append("No findings to report.")
        return "\n".join(lines)

    for finding in ctx.findings:
        sev = finding.get("severity", "info")
        lines += [
            f"## [{sev.upper()}] {finding.get('name') or finding.get('check_id')}",
            f"**Asset:** `{finding.get('location', '')}`  ",
            f"**Detection:** {finding.get('module', 'nuclei')} / `{finding.get('check_id', '')}`",
            "",
            "### Description",
            finding.get("description") or "Detected by ExactSurface's external scan.",
            "",
            "### Steps to Reproduce",
            _reproduction(finding),
            "",
            "### Impact",
            _IMPACT.get(sev, _IMPACT["info"]),
            "",
        ]
        refs = finding.get("references") or []
        if refs:
            lines.append("### References")
            lines += [f"- {r}" for r in refs]
            lines.append("")
        lines.append("---")
        lines.append("")
    return "\n".join(lines)
