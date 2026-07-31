"""Attack-path narrative — turn correlated signals into the sentence a human repeats.

The correlator already knows that one host has four overlapping problems and scores it
accordingly. What it produces is a list. What sells the finding to the person who
approves the budget is a *story*: "an exposed staging host leaks an API key in its
JavaScript, and the admin panel behind it answers to a 403 bypass."

This module writes that sentence. It is presentation, not detection — it invents no
findings and asserts nothing the underlying evidence does not already support. Each
step names the finding it came from, so a reader can click through and check the claim
rather than take the narrative's word for it. That traceability is the point: a story
nobody can verify is marketing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit

from core.severity import Severity

#: Ordered attacker phases. A path reads in this order regardless of the order the
#: scanner happened to find things in, because that is how the attack would run.
_PHASE_ORDER = (
    "exposure", "foothold", "credentials", "access", "escalation", "impact",
)

#: module/check -> (phase, template). The template receives the finding's own detail.
_STEP_RULES: tuple[tuple[str, str, str, str], ...] = (
    # (match_on_module, match_on_check_substring, phase, phrasing)
    ("takeover", "", "exposure", "a subdomain that can be taken over outright"),
    ("domain_intel", "expiry", "exposure", "a domain that is about to expire"),
    ("domain_intel", "spf", "exposure", "an email domain that anyone can spoof"),
    ("domain_intel", "dmarc", "exposure", "an email domain that anyone can spoof"),
    ("js_mine", "source-map", "foothold", "a published source map exposing the original code"),
    ("js_mine", "", "foothold", "internal API routes named in the public JavaScript"),
    ("api_surface", "graphql", "foothold", "a GraphQL schema served to anyone who asks"),
    ("api_surface", "openapi", "foothold", "an API schema documenting every route"),
    ("api_surface", "robots", "foothold", "hidden paths listed in robots.txt"),
    ("secrets", "", "credentials", "a live credential left in a public response"),
    ("github_osint", "", "credentials", "a credential committed to a public repository"),
    ("cloud_buckets", "", "impact", "a cloud bucket readable by the public"),
    ("bypass_403", "", "access", "an access-control check that can be walked around"),
    ("http_misconfig", "cors", "access", "a CORS policy that hands data to any origin"),
    ("http_misconfig", "redirect", "access", "an open redirect usable to launder a phishing link"),
    ("scan", "default-login", "access", "a default login that still works"),
    ("scan", "exposed", "exposure", "an exposed administrative interface"),
    ("cve_watch", "", "escalation", "a known-exploited vulnerability in the software it runs"),
    ("service_scan", "", "escalation", "an administrative service reachable from the internet"),
    ("broken_links", "", "impact", "an outbound link an attacker can hijack"),
    ("supply_chain", "", "impact", "an unclaimed internal package name an attacker can publish"),
)

_SEVERITY_RANK = {
    Severity.CRITICAL: 4, Severity.HIGH: 3, Severity.MEDIUM: 2,
    Severity.LOW: 1, Severity.INFO: 0,
}


@dataclass(frozen=True)
class Step:
    """One link in the chain, always traceable back to a finding."""

    phase: str
    text: str
    finding_id: str  # fingerprint — the UI links straight to the evidence
    check_id: str
    severity: str


@dataclass(frozen=True)
class AttackPath:
    host: str
    headline: str
    summary: str
    steps: list[Step] = field(default_factory=list)
    severity: str = Severity.INFO.value
    risk_score: int = 0

    @property
    def is_real_path(self) -> bool:
        """Two or more phases is a path. One finding is just a finding, and calling it
        an attack chain would be exactly the inflation this product exists to avoid."""
        return len({s.phase for s in self.steps}) >= 2


def _host_of(value: str) -> str:
    if "://" in (value or ""):
        return (urlsplit(value).hostname or "").lower()
    return (value or "").lower().rstrip(".")


def _classify(finding: dict) -> tuple[str, str] | None:
    module = str(finding.get("module") or "").lower()
    check = str(finding.get("check_id") or "").lower()
    name = str(finding.get("name") or "").lower()
    best: tuple[str, str] | None = None
    for want_module, want_check, phase, phrasing in _STEP_RULES:
        if want_module and want_module != module:
            continue
        if want_check and want_check not in check and want_check not in name:
            continue
        # Keep matching: later rules are the generic fallback for the same module,
        # earlier ones are more specific, so the FIRST match wins.
        best = (phase, phrasing)
        break
    return best


def build_paths(findings: list[dict], *, min_severity: Severity = Severity.LOW) -> list[AttackPath]:
    """Group findings per host into ordered, human-readable attack paths.

    Only hosts whose findings span two or more attacker phases produce a path. That
    threshold is deliberate — a page full of one-step "chains" would make the feature
    worthless and the product less trustworthy.
    """
    by_host: dict[str, list[Step]] = {}
    scores: dict[str, int] = {}
    worst: dict[str, Severity] = {}

    for finding in findings:
        try:
            sev = Severity(str(finding.get("severity") or "info"))
        except ValueError:
            sev = Severity.INFO
        if _SEVERITY_RANK[sev] < _SEVERITY_RANK[min_severity]:
            continue
        classified = _classify(finding)
        if not classified:
            continue
        host = _host_of(str(finding.get("location") or ""))
        if not host:
            continue
        phase, phrasing = classified
        by_host.setdefault(host, []).append(
            Step(
                phase=phase,
                text=phrasing,
                finding_id=str(finding.get("fingerprint") or ""),
                check_id=str(finding.get("check_id") or ""),
                severity=sev.value,
            )
        )
        scores[host] = scores.get(host, 0) + _SEVERITY_RANK[sev] * 10
        if _SEVERITY_RANK[sev] > _SEVERITY_RANK[worst.get(host, Severity.INFO)]:
            worst[host] = sev

    paths: list[AttackPath] = []
    for host, steps in by_host.items():
        # One step per phase — the strongest — so the story stays readable.
        by_phase: dict[str, Step] = {}
        for step in steps:
            existing = by_phase.get(step.phase)
            if existing is None or _SEVERITY_RANK[Severity(step.severity)] > _SEVERITY_RANK[
                Severity(existing.severity)
            ]:
                by_phase[step.phase] = step
        ordered = [by_phase[p] for p in _PHASE_ORDER if p in by_phase]
        if len(ordered) < 2:
            continue

        chain = " → ".join(s.text for s in ordered)
        severity = worst.get(host, Severity.INFO)
        paths.append(
            AttackPath(
                host=host,
                headline=f"{host}: {ordered[0].text} leads to {ordered[-1].text}",
                summary=(
                    f"On {host}, an attacker starting with nothing but your domain finds "
                    f"{chain}. Each step below links to the finding it came from."
                ),
                steps=ordered,
                severity=severity.value,
                risk_score=min(100, scores.get(host, 0)),
            )
        )

    paths.sort(key=lambda p: (_SEVERITY_RANK[Severity(p.severity)], p.risk_score), reverse=True)
    return paths
