"""Alert policy — what a program actually pages you about (§ notifications).

The notify pipeline delivers new signals to channels; this policy is the per-program
(and account-default) gate that decides *which* signals are worth an alert. It mirrors
the cadence/timeout override model: built-in defaults ← tenant defaults ← program
overrides (most specific wins), each a partial dict.

Two families of alert:
  * vulnerability signals (findings / secrets / leaks / CVEs) — gated by a severity
    floor + per-family on/off + a CVSS floor for CVEs;
  * change events (a new subdomain appears, a new port opens) — gated by an on/off
    toggle and, for ports, an nmap-style port filter. Change events only fire AFTER
    the initial baseline scan, so the first enumeration doesn't page you for every
    subdomain it finds.
"""

from __future__ import annotations

from core.severity import Severity

_SEVERITY_VALUES = {s.value for s in Severity}

#: bool on/off toggles (one per alert family / event).
_BOOL_KEYS = (
    "alert_findings",
    "alert_secrets",
    "alert_leaks",
    "alert_cves",
    "alert_new_assets",
    "alert_new_ports",
)

#: built-in policy — a sensible default that alerts on real exposure without spam.
DEFAULT_ALERT_POLICY: dict = {
    "finding_min_severity": "medium",  # floor for finding/secret/leak/cve alerts
    "alert_findings": True,
    "alert_secrets": True,
    "alert_leaks": True,
    "alert_cves": True,
    "cve_min_cvss": 0.0,  # additional CVE floor (0 = no CVSS gate)
    "alert_new_assets": True,  # a new subdomain appeared after baseline
    "alert_new_ports": True,  # a new open port appeared after baseline
    "port_filter": "",  # nmap-style ("22,80,443" / "1-1024"); "" = any port
}


def clean_port_spec(spec: str) -> str:
    """Normalise an nmap-style port spec, dropping anything invalid. ``"80, 22,1-100,x"``
    → ``"80,22,1-100"``; an all-invalid spec → ``""`` (meaning "any port")."""
    out: list[str] = []
    for tok in (spec or "").replace(" ", "").split(","):
        if not tok:
            continue
        if "-" in tok:
            lo, _, hi = tok.partition("-")
            if lo.isdigit() and hi.isdigit() and 1 <= int(lo) <= 65535 and 1 <= int(hi) <= 65535:
                out.append(f"{int(lo)}-{int(hi)}")
        elif tok.isdigit() and 1 <= int(tok) <= 65535:
            out.append(str(int(tok)))
    return ",".join(out)


def port_matches(spec: str, port: int) -> bool:
    """True if *port* falls in the (already-cleanable) *spec*. Empty spec = any port."""
    spec = clean_port_spec(spec)
    if not spec:
        return True
    for tok in spec.split(","):
        if "-" in tok:
            lo, _, hi = tok.partition("-")
            lo_i, hi_i = int(lo), int(hi)
            if lo_i > hi_i:
                lo_i, hi_i = hi_i, lo_i
            if lo_i <= port <= hi_i:
                return True
        elif int(tok) == port:
            return True
    return False


def sanitize_alert_policy(overrides: dict | None) -> dict:
    """Keep only recognised keys with valid values (a partial dict). Unknown keys and
    bad values are dropped so persisted config can never break the notify stage."""
    out: dict = {}
    o = overrides or {}
    sev = str(o.get("finding_min_severity", "")).lower()
    if sev in _SEVERITY_VALUES:
        out["finding_min_severity"] = sev
    for key in _BOOL_KEYS:
        if key in o:
            out[key] = bool(o[key])
    if "cve_min_cvss" in o:
        try:
            out["cve_min_cvss"] = min(10.0, max(0.0, float(o["cve_min_cvss"])))
        except (TypeError, ValueError):
            pass
    if "port_filter" in o:
        out["port_filter"] = clean_port_spec(str(o["port_filter"]))
    return out


def effective_alert_policy(
    program_overrides: dict | None = None, tenant_defaults: dict | None = None
) -> dict:
    """Resolve the policy a program actually alerts on: built-in defaults, overlaid by
    the tenant's account defaults, overlaid by the program's own overrides."""
    merged = dict(DEFAULT_ALERT_POLICY)
    merged.update(sanitize_alert_policy(tenant_defaults))
    merged.update(sanitize_alert_policy(program_overrides))
    return merged


def meets_severity_floor(severity: str, policy: dict) -> bool:
    """True if *severity* is at or above the policy's finding severity floor."""
    try:
        floor = Severity(policy.get("finding_min_severity", "medium")).rank
    except ValueError:
        floor = Severity.MEDIUM.rank
    try:
        return Severity(severity).rank >= floor
    except ValueError:
        return False
