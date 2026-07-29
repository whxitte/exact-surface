"""Email-spoofing exposure from DNS records (SPF / DMARC / DKIM).

An attacker with only a domain checks this within the first minute, because a domain
without a DMARC reject policy can be spoofed in phishing that passes every technical
check the recipient's mail server makes. It is the single most-reported finding in
external assessments, and it costs nothing to look for: the records are plain DNS TXT.

This module is pure — it parses records the caller supplies and returns findings. No
network, no state, fully unit-tested. ``pipelines/email_security.py`` does the lookups.

References for the rules encoded here: RFC 7208 (SPF), RFC 7489 (DMARC).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from core.severity import Severity

#: SPF "all" mechanisms, from strictest to weakest, with what each actually means.
_SPF_ALL = {
    "-all": ("fail", "hard fail — unlisted senders are rejected (strongest)"),
    "~all": ("softfail", "soft fail — unlisted senders are accepted but marked"),
    "?all": ("neutral", "neutral — the record asserts nothing, offering no protection"),
    "+all": ("pass", "pass — explicitly authorises the whole internet to send as you"),
}

#: SPF is capped at 10 DNS-querying mechanisms (RFC 7208 §4.6.4); beyond that,
#: evaluation fails permanently and the policy silently stops protecting anything.
_SPF_LOOKUP_MECHANISMS = ("include:", "a:", "mx:", "ptr", "exists:", "redirect=")
SPF_MAX_LOOKUPS = 10

#: DKIM selectors worth probing when we don't know the real one. Cheap, and a hit
#: proves signing is configured for that provider.
COMMON_DKIM_SELECTORS: tuple[str, ...] = (
    "default", "google", "selector1", "selector2", "k1", "dkim", "mail", "s1", "s2",
    "zoho", "mandrill", "sendgrid", "everlytickey1", "protonmail",
)


@dataclass(frozen=True)
class EmailFinding:
    """One email-security issue, in the shape the pipeline turns into a Finding."""

    check_id: str
    name: str
    severity: Severity
    detail: str
    record: str  # the exact record we judged, so the user can verify it themselves
    remediation: str


def _txt_records(records: list[str], prefix: str) -> list[str]:
    return [r.strip() for r in records if r.strip().lower().startswith(prefix)]


# -- SPF ---------------------------------------------------------------------
def parse_spf(txt_records: list[str]) -> tuple[str | None, list[EmailFinding]]:
    """Return the SPF record (if any) plus findings about it."""
    spf = _txt_records(txt_records, "v=spf1")
    if not spf:
        return None, [
            EmailFinding(
                "email-spf-missing",
                "No SPF record — anyone can send mail as this domain",
                Severity.MEDIUM,
                "The domain publishes no SPF record, so receiving mail servers have no "
                "list of authorised senders and cannot tell a forgery from a real message.",
                "(no v=spf1 TXT record)",
                "Publish a TXT record starting with v=spf1 that lists your senders and "
                "ends with -all.",
            )
        ]

    if len(spf) > 1:
        # RFC 7208: more than one SPF record is a permanent error — the policy is
        # ignored entirely, which is worse than a weak policy because it looks fine.
        return spf[0], [
            EmailFinding(
                "email-spf-multiple",
                "Multiple SPF records — the policy is invalid and ignored",
                Severity.MEDIUM,
                f"{len(spf)} SPF records are published. RFC 7208 makes this a permanent "
                "error, so receivers ignore SPF completely and the domain is unprotected.",
                " | ".join(spf),
                "Merge them into a single v=spf1 record.",
            )
        ]

    record = spf[0]
    findings: list[EmailFinding] = []
    lowered = record.lower()

    mechanism = next((m for m in _SPF_ALL if m in lowered), None)
    if mechanism is None:
        findings.append(
            EmailFinding(
                "email-spf-no-all",
                "SPF record has no 'all' mechanism",
                Severity.LOW,
                "Without a trailing all mechanism the policy is open-ended: senders not "
                "matched by any rule are treated as neutral.",
                record,
                "End the record with -all (or ~all while you are still testing).",
            )
        )
    elif mechanism == "+all":
        findings.append(
            EmailFinding(
                "email-spf-all-pass",
                "SPF authorises the entire internet (+all)",
                Severity.HIGH,
                "The record ends in +all, which explicitly tells receivers that any host "
                "on the internet may send mail as this domain. This is worse than having "
                "no SPF at all, because it actively vouches for forgeries.",
                record,
                "Replace +all with -all immediately.",
            )
        )
    elif mechanism == "?all":
        findings.append(
            EmailFinding(
                "email-spf-all-neutral",
                "SPF policy is neutral (?all) — no protection",
                Severity.LOW,
                "A neutral policy asserts nothing about unlisted senders, so it does not "
                "hinder spoofing.",
                record,
                "Change ?all to -all once your legitimate senders are listed.",
            )
        )

    lookups = sum(lowered.count(m) for m in _SPF_LOOKUP_MECHANISMS)
    if lookups > SPF_MAX_LOOKUPS:
        findings.append(
            EmailFinding(
                "email-spf-too-many-lookups",
                f"SPF exceeds the {SPF_MAX_LOOKUPS}-lookup limit ({lookups} found)",
                Severity.LOW,
                "RFC 7208 caps SPF at 10 DNS-querying mechanisms. Past that, evaluation "
                "returns permerror and receivers stop honouring the policy — so it "
                "silently protects nothing while still looking correct.",
                record,
                "Flatten includes or consolidate senders to get back under 10 lookups.",
            )
        )
    return record, findings


# -- DMARC -------------------------------------------------------------------
def parse_dmarc(txt_records: list[str]) -> tuple[str | None, list[EmailFinding]]:
    """Return the DMARC record (from ``_dmarc.<domain>``) plus findings."""
    dmarc = _txt_records(txt_records, "v=dmarc1")
    if not dmarc:
        return None, [
            EmailFinding(
                "email-dmarc-missing",
                "No DMARC record — the domain can be spoofed in phishing",
                Severity.MEDIUM,
                "Without DMARC, a receiving mail server has no instruction on what to do "
                "with mail that fails SPF/DKIM, and by default it delivers it. This is "
                "what makes convincing phishing 'from' your domain possible.",
                "(no v=DMARC1 TXT record at _dmarc)",
                "Publish _dmarc TXT: v=DMARC1; p=none; rua=mailto:you@domain — then "
                "tighten to p=quarantine and finally p=reject once reports look clean.",
            )
        ]

    record = dmarc[0]
    tags = dict(
        re.findall(r"(\w+)\s*=\s*([^;]+)", record.replace(" ", "")),
    )
    policy = (tags.get("p") or "").lower()
    findings: list[EmailFinding] = []

    if policy == "none":
        findings.append(
            EmailFinding(
                "email-dmarc-policy-none",
                "DMARC is monitor-only (p=none) — spoofed mail is still delivered",
                Severity.LOW,
                "p=none asks receivers to report failures but deliver the mail anyway. It "
                "is the right first step, but on its own it stops no phishing.",
                record,
                "Move to p=quarantine, then p=reject, once your reports show legitimate "
                "senders passing.",
            )
        )
    elif policy not in ("quarantine", "reject"):
        findings.append(
            EmailFinding(
                "email-dmarc-policy-invalid",
                "DMARC record has no valid policy tag",
                Severity.MEDIUM,
                "The record does not carry a usable p= value, so receivers cannot apply "
                "any policy and treat the domain as unprotected.",
                record,
                "Set p=reject (or p=quarantine while ramping up).",
            )
        )

    if policy in ("quarantine", "reject"):
        pct = tags.get("pct")
        if pct and pct.isdigit() and int(pct) < 100:
            findings.append(
                EmailFinding(
                    "email-dmarc-partial-pct",
                    f"DMARC policy applies to only {pct}% of mail",
                    Severity.LOW,
                    f"pct={pct} means {100 - int(pct)}% of failing mail is still delivered "
                    "normally, leaving a usable gap for phishing.",
                    record,
                    "Remove the pct tag (or set pct=100) once you are confident.",
                )
            )

    if not tags.get("rua"):
        findings.append(
            EmailFinding(
                "email-dmarc-no-reporting",
                "DMARC has no aggregate-report address (rua)",
                Severity.INFO,
                "Without rua you receive no visibility into who is sending as your domain, "
                "which is the main reason to deploy DMARC in the first place.",
                record,
                "Add rua=mailto:dmarc@yourdomain.",
            )
        )
    return record, findings


# -- DKIM --------------------------------------------------------------------
def parse_dkim(selector_records: dict[str, list[str]]) -> tuple[list[str], list[EmailFinding]]:
    """Given ``{selector: txt_records}``, return the selectors that are configured.

    Absence is reported at INFO only: DKIM selectors are arbitrary, so not finding one
    among the common names is weak evidence — we say exactly that rather than claiming
    DKIM is missing.
    """
    if not selector_records:
        # Nothing was probed, so we know nothing. Reporting "not found" here would be a
        # false positive — silence is the honest answer.
        return [], []
    found = [
        sel
        for sel, records in selector_records.items()
        if any("v=dkim1" in r.lower() or "p=" in r.lower() for r in records)
    ]
    if found:
        return found, []
    return [], [
        EmailFinding(
            "email-dkim-not-found",
            "No DKIM signing key found on common selectors",
            Severity.INFO,
            "None of the widely-used selector names published a DKIM key. Selectors are "
            "arbitrary, so this is not proof DKIM is absent — but combined with a weak "
            "DMARC policy it suggests signing may not be deployed.",
            f"checked: {', '.join(sorted(selector_records))}",
            "Confirm with your mail provider which selector you use, and that DKIM "
            "signing is enabled.",
        )
    ]


def analyse(
    *,
    spf_txt: list[str],
    dmarc_txt: list[str],
    dkim_selectors: dict[str, list[str]] | None = None,
) -> tuple[dict, list[EmailFinding]]:
    """Full assessment. Returns (summary, findings) — the summary is what the UI shows
    as the domain's email posture, the findings become real Finding records."""
    spf_record, spf_findings = parse_spf(spf_txt)
    dmarc_record, dmarc_findings = parse_dmarc(dmarc_txt)
    dkim_found, dkim_findings = parse_dkim(dkim_selectors or {})

    lowered = (dmarc_record or "").lower()
    policy = "none"
    for p in ("reject", "quarantine", "none"):
        if f"p={p}" in lowered.replace(" ", ""):
            policy = p
            break

    summary = {
        "spf": spf_record,
        "spf_present": spf_record is not None,
        "dmarc": dmarc_record,
        "dmarc_present": dmarc_record is not None,
        "dmarc_policy": policy if dmarc_record else None,
        "dkim_selectors": dkim_found,
        # The headline the UI shows: can someone convincingly spoof this domain?
        "spoofable": dmarc_record is None or policy == "none",
    }
    return summary, [*spf_findings, *dmarc_findings, *dkim_findings]
