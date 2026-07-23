"""Self-contained interactive HTML report (module 30).

Returns a single HTML document with inline CSS (dark theme, matching the app) —
portable, emailable, printable. All dynamic content is HTML-escaped; secrets/leaks
render only their masked values (§9c).
"""

from __future__ import annotations

from html import escape

from modules.reporting.context import ReportContext

_SEV_COLOR = {
    "critical": "#EF4444",
    "high": "#F97316",
    "medium": "#F59E0B",
    "low": "#0EA5E9",
    "info": "#71717A",
}


def _badge(sev: str) -> str:
    color = _SEV_COLOR.get(sev, _SEV_COLOR["info"])
    return (
        f'<span style="background:{color}22;color:{color};border:1px solid {color}55;'
        f"border-radius:9999px;padding:2px 8px;font-size:11px;text-transform:uppercase;"
        f'font-weight:600">{escape(sev)}</span>'
    )


def _stat(label: str, value: int) -> str:
    return (
        f'<div style="background:#141416;border:1px solid #26262b;border-radius:10px;'
        f'padding:16px;min-width:110px">'
        f'<div style="font-size:24px;font-weight:600">{value}</div>'
        f'<div style="font-size:11px;text-transform:uppercase;color:#8b8b93">{escape(label)}</div>'
        f"</div>"
    )


def render_html(ctx: ReportContext) -> str:
    c = ctx.counts
    stats = "".join(
        _stat(k, v)
        for k, v in [
            ("Assets", c["assets"]),
            ("Endpoints", c["endpoints"]),
            ("Findings", c["findings"]),
            ("Secrets", c["secrets"]),
            ("CVE matches", c["cve_matches"]),
            ("Open ports", c["open_ports"]),
        ]
    )

    issue_rows = (
        "".join(
            f"<tr><td>{escape(i.host)}</td><td>{i.risk_score}/100</td>"
            f"<td>{'chain' if i.is_chain else '—'}</td>"
            f"<td>{escape(', '.join(i.signals[:5]))}</td></tr>"
            for i in ctx.top_issues
        )
        or '<tr><td colspan="4" style="color:#8b8b93">No correlated issues.</td></tr>'
    )

    finding_rows = (
        "".join(
            f"<tr><td>{_badge(f.get('severity', 'info'))}</td>"
            f"<td>{escape(f.get('name') or f.get('check_id', ''))}</td>"
            f"<td style='font-family:monospace;font-size:12px'>{escape(f.get('location', ''))}</td>"
            f"<td>{escape(f.get('module', ''))}</td></tr>"
            for f in ctx.findings
        )
        or '<tr><td colspan="4" style="color:#8b8b93">No findings.</td></tr>'
    )

    secret_rows = (
        "".join(
            f"<tr><td>{escape(s.get('kind', ''))}</td>"
            f"<td style='font-family:monospace'>{escape(s.get('masked', ''))}</td>"
            f"<td style='font-family:monospace;font-size:12px'>{escape(s.get('source_locator', ''))}</td></tr>"
            for s in ctx.secrets
        )
        or '<tr><td colspan="3" style="color:#8b8b93">No exposed secrets.</td></tr>'
    )

    th = 'style="text-align:left;padding:8px;border-bottom:1px solid #26262b;color:#8b8b93;font-size:12px"'
    td_css = "td{padding:8px;border-bottom:1px solid #1c1c20;font-size:14px}"

    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>ExactSurface Report — {escape(ctx.program)}</title>
<style>
body{{background:#0a0a0b;color:#fafafa;font-family:system-ui,-apple-system,sans-serif;margin:0;padding:40px;max-width:1000px;margin:0 auto}}
h1{{font-size:24px;margin:0 0 4px}} h2{{font-size:16px;margin:32px 0 12px}}
.muted{{color:#8b8b93;font-size:13px}} table{{width:100%;border-collapse:collapse}} {td_css}
</style></head><body>
<h1>ExactSurface Attack-Surface Report</h1>
<div class="muted">{escape(ctx.program)} · generated {escape(ctx.generated_at)} · detection only</div>
<div style="display:flex;gap:12px;flex-wrap:wrap;margin-top:24px">{stats}</div>

<h2>Top Risks</h2>
<table><thead><tr><th {th}>Host</th><th {th}>Risk</th><th {th}>Type</th><th {th}>Signals</th></tr></thead>
<tbody>{issue_rows}</tbody></table>

<h2>Findings</h2>
<table><thead><tr><th {th}>Severity</th><th {th}>Name</th><th {th}>Location</th><th {th}>Module</th></tr></thead>
<tbody>{finding_rows}</tbody></table>

<h2>Exposed Secrets <span class="muted">(masked)</span></h2>
<table><thead><tr><th {th}>Kind</th><th {th}>Value</th><th {th}>Location</th></tr></thead>
<tbody>{secret_rows}</tbody></table>
<hr><div class="muted" style="font-size:11px">{escape(ctx.watermark)}</div>
</body></html>"""
