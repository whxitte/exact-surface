"""Declarative registry of every capability module (§6).

The daemon prints this on ``--dry-run`` so operators can see, at a glance, which
modules exist, which external binary each needs, which build phase it belongs to,
and whether it is enabled. ``masscan`` ships present-but-disabled (ADR-0004).

Keeping the roster declarative (rather than importing every wrapper) means health
checks and the dry-run work before the wrappers are implemented, and the required
external binaries can be verified independently of the Python code.
"""

from __future__ import annotations

from dataclasses import dataclass

from core.scope import Action


@dataclass(frozen=True)
class ModuleSpec:
    name: str
    category: str
    binary: str | None  # external tool required, or None for pure-Python / API
    phase: str  # "1" | "2" | "3"
    requires: Action  # minimum scope action needed to run
    enabled: bool = True
    note: str = ""


MODULE_REGISTRY: tuple[ModuleSpec, ...] = (
    # -- Phase 1: core pipeline --------------------------------------------
    ModuleSpec("subfinder", "recon", "subfinder", "1", Action.PASSIVE_RECON),
    ModuleSpec("crtsh", "recon", None, "1", Action.PASSIVE_RECON),
    ModuleSpec(
        "uncover",
        "recon",
        "uncover",
        "1",
        Action.PASSIVE_RECON,
        note="unifies Shodan/Censys/Fofa/Zoomeye",
    ),
    ModuleSpec("dnsx", "recon", "dnsx", "1", Action.PASSIVE_RECON),
    ModuleSpec(
        "cloudlist",
        "recon",
        "cloudlist",
        "2",
        Action.PASSIVE_RECON,
        note="customer's OWN cloud credentials, read-only, never leave their deployment",
    ),
    ModuleSpec(
        "alterx",
        "recon",
        "alterx",
        "1",
        Action.PASSIVE_RECON,
        note="subdomain permutations; only DNS-confirmed names become assets",
    ),
    ModuleSpec("httpx", "probing", "httpx", "1", Action.HTTP_PROBE),
    ModuleSpec("tlsx", "probing", "tlsx", "1", Action.TLS_INSPECT),
    ModuleSpec(
        "nuclei",
        "scanning",
        "nuclei",
        "1",
        Action.ACTIVE_SCAN,
        note="safe policy: exclude dos,intrusive,fuzz",
    ),
    ModuleSpec(
        "secretfinder",
        "scanning",
        None,
        "1",
        Action.HTTP_PROBE,
        note="regex-based JS/content secret detection (no external binary)",
    ),
    ModuleSpec(
        "trufflehog",
        "scanning",
        "trufflehog",
        "1",
        Action.HTTP_PROBE,
        note="800+ verified detectors; regex secretfinder stays as the fallback",
    ),
    ModuleSpec("katana", "crawling", "katana", "1", Action.HTTP_PROBE),
    ModuleSpec("waybackurls", "crawling", "waybackurls", "1", Action.PASSIVE_RECON),
    ModuleSpec("gau", "crawling", "gau", "1", Action.PASSIVE_RECON),
    # -- Phase 2: attacker's edge ------------------------------------------
    ModuleSpec(
        "naabu", "ports", "naabu", "2", Action.PORT_SCAN, note="rate-capped; replaces masscan in v1"
    ),
    ModuleSpec(
        "masscan",
        "ports",
        "masscan",
        "2",
        Action.PORT_SCAN,
        enabled=False,
        note="NOT SHIPPED in v1 — no wrapper, binary not installed (ADR-0004)",
    ),
    ModuleSpec(
        "nmap", "ports", "nmap", "2", Action.PORT_SCAN, note="--max-rate capped, safe scripts only"
    ),
    ModuleSpec("feroxbuster", "content_discovery", "feroxbuster", "2", Action.CONTENT_DISCOVERY),
    ModuleSpec("ffuf", "content_discovery", "ffuf", "2", Action.CONTENT_DISCOVERY),
    ModuleSpec("wordlist_selector", "content_discovery", None, "2", Action.CONTENT_DISCOVERY),
    ModuleSpec(
        "arjun",
        "content_discovery",
        "arjun",
        "2",
        Action.CONTENT_DISCOVERY,
        note="hidden parameter discovery; built-in probe is the fallback",
    ),
    ModuleSpec(
        "js_miner",
        "scanning",
        None,
        "2",
        Action.HTTP_PROBE,
        note="mines the app's own bundles for routes/hosts/source maps",
    ),
    ModuleSpec(
        "broken_links",
        "osint",
        None,
        "2",
        Action.PASSIVE_RECON,
        note="outbound links to unregistered domains / unclaimed social handles",
    ),
    ModuleSpec(
        "email_security",
        "osint",
        None,
        "2",
        Action.PASSIVE_RECON,
        note="SPF/DMARC/DKIM spoofability from DNS TXT (RFC 7208/7489)",
    ),
    ModuleSpec(
        "rdap",
        "osint",
        None,
        "2",
        Action.PASSIVE_RECON,
        note="registrar, expiry, transfer lock, DNSSEC via RDAP (not legacy WHOIS)",
    ),
    ModuleSpec(
        "bypass_403",
        "scanning",
        None,
        "2",
        Action.HTTP_PROBE,
        note="on-demand only; detects access-control bypass, never exploits it",
    ),
    ModuleSpec("github_leaks", "osint", None, "2", Action.PASSIVE_RECON),
    ModuleSpec("asn_mapper", "osint", "asnmap", "2", Action.PASSIVE_RECON),
    ModuleSpec(
        "cloud_buckets",
        "osint",
        # No binary: the permutation half of §6 module 18 is pure HTTP against the
        # providers' public endpoints. The `cloudlist` half (enumerating a customer's
        # cloud assets via provider APIs) is NOT implemented — it would require the
        # customer's cloud credentials, a trust escalation we have not taken.
        None,
        "2",
        Action.PASSIVE_RECON,
        note="name permutation over S3/GCS/Azure; publicly-listable buckets only",
    ),
    ModuleSpec(
        "preview_env",
        "osint",
        None,
        "2",
        Action.PASSIVE_RECON,
        # Implemented as a classifier in core, not a modules/osint/ wrapper: it needs
        # no tool and no I/O of its own. Applied to every host at ingest + uncover,
        # surfaced as Asset.is_ephemeral.
        note="core.fingerprint.is_ephemeral_host — Vercel/Netlify/CF-Pages/staging envs",
    ),
    ModuleSpec(
        "dork",
        "dorking",
        None,
        "2",
        Action.PASSIVE_RECON,
        note="engines: Google CSE → Brave → SerpAPI (first configured wins)",
    ),
    ModuleSpec(
        "cve_feed",
        "intelligence",
        None,
        "2",
        Action.PASSIVE_RECON,
        note="NVD+KEV+GHSA, confidence-scored matches",
    ),
    ModuleSpec(
        "nuclei_watch",
        "intelligence",
        "nuclei",
        "2",
        Action.PASSIVE_RECON,
        note="template lister is injected — nuclei -tl contract unverified against the pin",
    ),
    ModuleSpec("delta_monitor", "intelligence", None, "2", Action.HTTP_PROBE),
    ModuleSpec("correlator", "intelligence", None, "2", Action.PASSIVE_RECON),
    # -- Phase 3: expansion ------------------------------------------------
    ModuleSpec(
        "dalfox",
        "scanning",
        "dalfox",
        "3",
        Action.ACTIVE_SCAN,
        enabled=False,
        note="opt-in XSS fuzzer",
    ),
    ModuleSpec("nikto", "scanning", "nikto", "3", Action.ACTIVE_SCAN, enabled=False),
    ModuleSpec("html_report", "reporting", None, "3", Action.PASSIVE_RECON),
    ModuleSpec("pdf_report", "reporting", None, "3", Action.PASSIVE_RECON),
    ModuleSpec("discord", "notification", None, "3", Action.PASSIVE_RECON),
    ModuleSpec("telegram", "notification", None, "3", Action.PASSIVE_RECON),
    ModuleSpec("slack", "notification", None, "3", Action.PASSIVE_RECON),
    ModuleSpec("email", "notification", None, "3", Action.PASSIVE_RECON),
    ModuleSpec("webhook", "notification", None, "3", Action.PASSIVE_RECON),
)


def enabled_modules() -> tuple[ModuleSpec, ...]:
    return tuple(m for m in MODULE_REGISTRY if m.enabled)


def required_binaries() -> list[str]:
    """Distinct external binaries required by enabled modules (for health checks)."""
    seen: dict[str, None] = {}
    for m in enabled_modules():
        if m.binary:
            seen.setdefault(m.binary, None)
    return sorted(seen)
