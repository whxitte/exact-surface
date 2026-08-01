"""Seed the public demo with realistic data covering every screen.

Run any time:

    python -m scripts.seed_demo                 # wipe + reseed
    python -m scripts.seed_demo --keep-existing # add without wiping

The goal is that a visitor clicking through the demo sees a *complete* product: every
tab populated, every severity represented, findings that show their reproduction
command, an attack path, a running scan with live logs, and history that makes the
change-tracking meaningful. An empty tab in a demo reads as a missing feature.

The data is fictional and self-consistent. `demo.exactsurface.com` and its subdomains
are used throughout so nothing here points at a real third party — a demo that displays
findings against someone else's domain would be exactly the kind of thing this product
exists to warn people about.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import random
from datetime import UTC, datetime, timedelta
from typing import Any

APEX = "demo.exactsurface.com"
TENANT_ID = "t_demo"
PROGRAM_ID = "prog_demo"
USER_ID = "u_demo"
DEMO_EMAIL = "demo@exactsurface.com"
#: Shown publicly on the marketing page. Not a secret and not reused anywhere.
DEMO_PASSWORD = "seeThe.Surface2026"  # noqa: S105 - deliberately public demo credential

NOW = datetime.now(UTC)


def _ago(**kw) -> datetime:
    return NOW - timedelta(**kw)


def _spread(low: int, high: int) -> int:
    """Cosmetic variation in demo timestamps and counts.

    `random` is fine here and nowhere else in this codebase: nothing security-relevant
    is decided by it — it only makes the seeded data look lived-in rather than uniform.
    """
    return random.randint(low, high)  # noqa: S311 - cosmetic only, see docstring


def _fp(*parts: object) -> str:
    return hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()[:32]


# -- the fictional estate ----------------------------------------------------
HOSTS: list[dict] = [
    # (hostname, ips, tech, status, title, interest, ephemeral)
    {"h": APEX, "ip": "203.0.113.10", "tech": ["nginx", "Next.js"], "code": 200,
     "title": "ExactSurface Demo — Home", "interest": "low"},
    {"h": f"www.{APEX}", "ip": "203.0.113.10", "tech": ["nginx", "Next.js"], "code": 200,
     "title": "ExactSurface Demo — Home", "interest": "low"},
    {"h": f"api.{APEX}", "ip": "203.0.113.11", "tech": ["nginx", "FastAPI"], "code": 200,
     "title": "Demo API", "interest": "high"},
    {"h": f"staging.{APEX}", "ip": "203.0.113.12", "tech": ["nginx", "React"], "code": 200,
     "title": "Staging — Demo", "interest": "critical", "ephemeral": True},
    {"h": f"admin.{APEX}", "ip": "203.0.113.13", "tech": ["Apache", "PHP"], "code": 403,
     "title": "Forbidden", "interest": "critical"},
    {"h": f"jenkins.{APEX}", "ip": "203.0.113.14", "tech": ["Jetty", "Jenkins"], "code": 200,
     "title": "Dashboard [Jenkins]", "interest": "critical"},
    {"h": f"mail.{APEX}", "ip": "203.0.113.15", "tech": [], "code": None,
     "title": None, "interest": "medium"},
    {"h": f"vpn.{APEX}", "ip": "203.0.113.16", "tech": ["OpenVPN"], "code": 200,
     "title": "VPN Portal", "interest": "high"},
    {"h": f"blog.{APEX}", "ip": "203.0.113.17", "tech": ["nginx", "WordPress"], "code": 200,
     "title": "Demo Blog", "interest": "medium"},
    {"h": f"legacy.{APEX}", "ip": "203.0.113.18", "tech": ["IIS", "ASP.NET"], "code": 200,
     "title": "Legacy Portal", "interest": "high"},
    {"h": f"cdn.{APEX}", "ip": "203.0.113.19", "tech": ["Cloudflare"], "code": 200,
     "title": "Assets", "interest": "noise"},
    {"h": f"old-shop.{APEX}", "ip": "", "tech": [], "code": None,
     "title": None, "interest": "high", "takeover": "Amazon S3"},
]

FINDINGS: list[dict] = [
    ("critical", "scan", "exposed-git-config", "Exposed .git repository",
     f"https://legacy.{APEX}/.git/config",
     "The full source repository is downloadable, including its commit history. Anyone "
     "can reconstruct the application source and read any credential ever committed.",
     f"curl -sk https://legacy.{APEX}/.git/config"),
    ("critical", "takeover", "subdomain-takeover-s3",
     f"Subdomain takeover possible: old-shop.{APEX}", f"old-shop.{APEX}",
     "This name is a dangling CNAME to an Amazon S3 bucket that no longer exists. "
     "Anyone can create a bucket with that name and serve content from your domain.",
     f"dig +short CNAME old-shop.{APEX}"),
    ("high", "secrets", "aws-access-key", "AWS access key exposed in JavaScript",
     f"https://staging.{APEX}/static/js/main.4f2a.js",
     "A live-looking AWS key is embedded in a public bundle. Keys in client-side code "
     "are readable by every visitor. Shown masked; the raw value is never stored.",
     f"curl -s https://staging.{APEX}/static/js/main.4f2a.js | grep -o 'AKIA[A-Z0-9]*'"),
    ("high", "http_misconfig", "cors-reflected-origin",
     "CORS policy accepts an arbitrary origin", f"https://api.{APEX}",
     "The server echoed our arbitrary Origin back in Access-Control-Allow-Origin and set "
     "Access-Control-Allow-Credentials: true. Any website a logged-in user visits can "
     "read authenticated responses from this host.",
     f"curl -sI https://api.{APEX} -H 'Origin: https://exactsurface-cors-probe.example.com'"),
    ("high", "cve_watch", "CVE-2024-23897",
     "Jenkins CLI arbitrary file read (KEV listed)", f"https://jenkins.{APEX}",
     "The Jenkins version fingerprinted here is affected by CVE-2024-23897, which CISA "
     "lists as known-exploited. It allows reading arbitrary files from the controller.",
     f"curl -s https://jenkins.{APEX}/login | grep -i 'jenkins-version'"),
    ("high", "domain_intel", "dmarc-missing", "Domain can be spoofed — no DMARC policy",
     APEX,
     "No DMARC record is published, so any mail server on the internet can send email "
     "that appears to come from this domain and it will not be rejected.",
     f"dig +short TXT _dmarc.{APEX}"),
    ("medium", "api_surface", "api-surface-graphql", "GraphQL introspection enabled",
     f"https://api.{APEX}/graphql",
     "One unauthenticated query returns the complete schema — 84 types and the Mutation "
     "root. An attacker gets the full API contract, including operations never linked.",
     f"curl -s -X POST https://api.{APEX}/graphql "
     "-d '{\"query\":\"{__schema{types{name}}}\"}'"),
    ("medium", "js_mine", "js-source-map-exposed",
     "Source map published alongside minified JavaScript",
     f"https://staging.{APEX}/static/js/main.4f2a.js",
     "A .map file is served next to this bundle. Anyone can download it and reconstruct "
     "the original source, including comments and internal file names.",
     f"curl -sI https://staging.{APEX}/static/js/main.4f2a.js.map"),
    ("medium", "http_misconfig", "open-redirect", "Open redirect via ?next=",
     f"https://{APEX}/login?next=/dashboard",
     "Setting ?next= to an external URL made the server respond 302 to it. Anyone can "
     "send a link that starts on this trusted domain and lands the victim elsewhere.",
     f"curl -sI 'https://{APEX}/login?next=https://example.org' | grep -i location"),
    ("medium", "supply_chain", "dependency-confusion-unclaimed-package",
     "Unclaimed package name referenced in public JS: @demo-internal/auth-client",
     f"https://{APEX}/static/js/vendor.9c1b.js",
     "This package is referenced in your published JavaScript but is not registered on "
     "npm. Anyone can publish that exact name and have their code installed in your build.",
     "curl -s -o /dev/null -w '%{http_code}' "
     "https://registry.npmjs.org/@demo-internal%2Fauth-client"),
    ("medium", "typosquat", "lookalike-domain-registered",
     "Lookalike domain registered with mail: dem0-exactsurface.com",
     "dem0-exactsurface.com",
     "This domain is registered and resolving. It was derived from yours by a homoglyph "
     "substitution, and it has MX records — it can send mail that reads as yours.",
     "dig +short dem0-exactsurface.com && dig +short MX dem0-exactsurface.com"),
    ("low", "tls", "tls-expiring-soon", "TLS certificate expires in 12 days",
     f"https://vpn.{APEX}",
     "The certificate for this host expires soon. An expired certificate on a VPN portal "
     "trains users to click through browser warnings.",
     f"echo | openssl s_client -connect vpn.{APEX}:443 2>/dev/null | openssl x509 -noout -dates"),
    ("low", "api_surface", "robots-discloses-sensitive-paths",
     "robots.txt lists 3 sensitive path(s)", f"https://{APEX}/robots.txt",
     "robots.txt asks search engines not to index these paths, which tells anyone who "
     "reads the file exactly where they are.\n\n  /admin/\n  /internal/\n  /backup/",
     f"curl -s https://{APEX}/robots.txt"),
    ("low", "broken_links", "broken-link-unregistered-domain",
     "Broken link hijack: old-partner-site.com is unregistered", f"https://blog.{APEX}/partners",
     "This page links to a domain that no longer resolves. An attacker can register it "
     "and serve content that inherits your page's trust.",
     "dig +short old-partner-site.com"),
    ("info", "domain_intel", "security-txt-present", "security.txt is published",
     f"https://{APEX}/.well-known/security.txt",
     "Researchers have a documented way to report issues. This is good practice and is "
     "recorded for completeness.",
     f"curl -s https://{APEX}/.well-known/security.txt"),
]

ENDPOINTS: list[tuple[str, str, int, str, list[str]]] = [
    (f"https://api.{APEX}/api/internal/v2/users", "js", 401, "", ["api", "internal"]),
    (f"https://api.{APEX}/api/internal/v2/billing", "js", 401, "", ["api", "internal", "payment"]),
    (f"https://api.{APEX}/graphql", "api_surface", 200, "", ["api", "graphql"]),
    (f"https://api.{APEX}/openapi.json", "api_surface", 200, "", ["api", "api-docs"]),
    (f"https://admin.{APEX}/admin/", "feroxbuster", 403, "Forbidden", ["admin", "auth"]),
    (f"https://admin.{APEX}/admin/users", "feroxbuster", 403, "Forbidden", ["admin"]),
    (f"https://legacy.{APEX}/.git/config", "feroxbuster", 200, "", ["exposure"]),
    (f"https://legacy.{APEX}/backup.zip", "feroxbuster", 200, "", ["exposure"]),
    (f"https://{APEX}/", "probe", 200, "ExactSurface Demo — Home", []),
    (f"https://{APEX}/login", "crawl", 200, "Sign in", ["auth"]),
    (f"https://{APEX}/robots.txt", "api_surface", 200, "", []),
    (f"https://staging.{APEX}/", "probe", 200, "Staging — Demo", []),
    (f"https://staging.{APEX}/static/js/main.4f2a.js", "crawl", 200, "", []),
    (f"https://blog.{APEX}/wp-admin/", "feroxbuster", 302, "", ["admin", "auth"]),
    (f"https://jenkins.{APEX}/login", "probe", 200, "Jenkins", ["auth", "admin"]),
]

STAGES = [
    "domain_intel", "ingest", "cloud_assets", "uncover", "reverse_dns", "probe", "tls",
    "takeover", "crawl", "content_discovery", "js_mine", "api_surface", "http_misconfig",
    "param_discovery", "broken_links", "port_scan", "service_scan", "scan", "secrets",
    "cve_watch", "github_osint", "cloud_buckets", "nuclei_watch", "dork", "supply_chain",
    "typosquat", "correlate", "notify",
]

LOG_LINES = [
    "scan started for demo.exactsurface.com (28 stages)",
    "stage domain_intel started (limit 180s)",
    "domain_intel demo.exactsurface.com: spoofable=True expires_in=284d → 2 finding(s), 1 new",
    "stage ingest started (limit 300s)",
    "discovering subdomains of demo.exactsurface.com (subfinder + crt.sh)",
    "found 47 candidate(s) (31 subfinder, 16 crt.sh); resolving with dnsx",
    "alterx generated 312 permutation candidate(s) to resolve",
    "alterx: 2/312 permutation(s) actually resolve — keeping only confirmed names",
    "dnsx resolved 12/14 in-scope host(s) to live IPs",
    "ingest complete: 47 candidates → 12 in-scope assets, 3 new",
    "stage probe started (limit 300s)",
    "httpx: 12 host(s) probed → 10 alive",
    "probe: staging.demo.exactsurface.com flagged CRITICAL (exposed staging environment)",
    "stage crawl started (limit 600s)",
    "katana: 1284 URL(s) from 10 host(s); gau added 412 archived",
    "stage js_mine started (limit 600s)",
    "js_mine: main.4f2a.js → 218 item(s), 34 interesting, 6 host(s)",
    "js_mine: source map found at main.4f2a.js.map",
    "stage api_surface started (limit 900s)",
    "api_surface: api.demo.exactsurface.com/robots.txt → 3 path(s)",
    "api_surface: API schema at https://api.demo.exactsurface.com/openapi.json",
    "api_surface: GraphQL at https://api.demo.exactsurface.com/graphql (medium)",
    "stage http_misconfig started (limit 600s)",
    "http_misconfig: CORS https://api.demo.exactsurface.com → allow-origin reflected, "
    "credentials=True",
    "http_misconfig: open redirect via ?next= on https://demo.exactsurface.com/login",
    "http_misconfig: 4 host(s) behind Cloudflare, 6 without",
    "stage scan started (limit 3600s)",
    "nuclei: 1 critical, 2 high, 4 medium across 10 host(s)",
    "stage secrets started (limit 600s)",
    "secrets: fetching 412 URL(s) for secret analysis",
    "secrets: AWS key found in staging.demo.exactsurface.com/static/js/main.4f2a.js (masked)",
    "stage correlate started (limit 120s)",
    "correlate: 3 host(s) with 2+ signals → 1 attack path",
]


async def _insert_all(mongo: Any, collection: str, docs: list[dict]) -> None:
    """Insert one at a time — the same call every repo in this codebase uses, so the
    seeder works against the in-memory fake as well as a real Mongo."""
    for doc in docs:
        await mongo.collection(collection).insert_one(doc)


async def seed(mongo: Any, *, wipe: bool = True) -> dict[str, int]:
    from api.auth import hash_password

    counts: dict[str, int] = {}

    if wipe:
        for name in (
            "tenants", "users", "groups", "programs", "authorizations", "assets",
            "endpoints", "findings", "secrets", "ports", "leaks", "cve_matches",
            "js_files", "deltas", "scan_runs", "schedule", "domain_intel",
            "notifications", "integrations", "api_keys",
        ):
            await mongo.collection(name).delete_many({})

    # -- tenant, owner, program, authorization -------------------------------
    await mongo.collection("tenants").insert_one({
        "tenant_id": TENANT_ID, "name": "Demo Corp", "plan": "business",
        "created_at": _ago(days=90),
    })
    await mongo.collection("users").insert_one({
        "tenant_id": TENANT_ID, "user_id": USER_ID, "email": DEMO_EMAIL,
        "password_hash": hash_password(DEMO_PASSWORD), "role": "owner",
        "email_verified": True, "group_ids": [], "created_at": _ago(days=90),
    })
    await mongo.collection("programs").insert_one({
        "tenant_id": TENANT_ID, "program_id": PROGRAM_ID, "apex_domain": APEX,
        "verified": True, "enabled": True, "verification_method": "dns_txt",
        "created_at": _ago(days=90), "initial_scan_completed_at": _ago(days=89),
        "enabled_modules": ["tls", "param_discovery", "typosquat"],
        "disabled_modules": [],
    })
    await mongo.collection("authorizations").insert_one({
        "tenant_id": TENANT_ID, "program_id": PROGRAM_ID, "authorized_by": USER_ID,
        "authorized_at": _ago(days=90), "apex_verified": True,
        "verification_method": "dns_txt", "ip_scope": [], "revoked": False,
    })
    counts["programs"] = 1

    # -- assets ---------------------------------------------------------------
    assets = []
    for i, h in enumerate(HOSTS):
        assets.append({
            "tenant_id": TENANT_ID, "program_id": PROGRAM_ID,
            "fingerprint": _fp("asset", h["h"]), "hostname": h["h"],
            "resolved_ips": [h["ip"]] if h["ip"] else [],
            "ip_class": "dedicated" if h["ip"] else None,
            "is_ephemeral": h.get("ephemeral", False),
            "monitored": True, "interest": h["interest"],
            "interest_reasons": (
                ["Exposed staging environment"] if h.get("ephemeral")
                else ["Jenkins CI/CD exposed"] if "jenkins" in h["h"] else []
            ),
            "dns_records": (
                {"a": [h["ip"]]} if h["ip"]
                else {"cname": ["old-shop.s3.amazonaws.com"]}
            ),
            "takeover_risk": h.get("takeover"),
            "source": "subfinder", "is_new": i < 2,
            "first_seen": _ago(days=90 - i), "last_seen": _ago(hours=2),
        })
    await _insert_all(mongo, "assets", assets)
    counts["assets"] = len(assets)

    # -- endpoints ------------------------------------------------------------
    eps = []
    for url, source, code, title, tags in ENDPOINTS:
        entry = {
            "tenant_id": TENANT_ID, "program_id": PROGRAM_ID,
            "fingerprint": _fp("ep", url), "url": url, "method": "GET",
            "status_code": code, "title": title or None, "tech": [],
            "source": source, "risk_tags": tags,
            "first_seen": _ago(days=30), "last_seen": _ago(hours=2),
        }
        if code == 403 and "admin/" in url:
            # A demonstrated 403 bypass — the blue label on the Endpoints tab.
            entry.update({
                "bypass_attempted": True,
                "bypass_checked_at": _ago(hours=3),
                "bypasses": [{
                    "technique": "header", "label": "X-Original-URL: /admin/",
                    "method": "GET", "url": url,
                    "request_headers": {"X-Original-URL": "/admin/"},
                    "status": 200, "length": 4821, "confidence": "high",
                    "evidence": "403 → 200 with a 4821-byte body containing 'User administration'",
                    "curl": f"curl -sk '{url}' -H 'X-Original-URL: /admin/'",
                }],
            })
        else:
            entry["bypass_attempted"] = code in (401, 403)
        eps.append(entry)
    await _insert_all(mongo, "endpoints", eps)
    counts["endpoints"] = len(eps)

    # -- findings -------------------------------------------------------------
    findings = []
    for i, (sev, module, check, name, loc, desc, repro) in enumerate(FINDINGS):
        findings.append({
            "tenant_id": TENANT_ID, "program_id": PROGRAM_ID,
            "fingerprint": _fp("finding", check, loc), "check_id": check,
            "module": module, "location": loc, "locator": "", "name": name,
            "description": desc, "severity": sev,
            "state": "confirmed" if i % 5 else "new",
            "is_new": i < 3, "reproduction": repro,
            "references": [], "cvss": 9.8 if sev == "critical" else None,
            "raw": {"demo": True},
            "first_seen": _ago(days=_spread(1, 60)), "last_seen": _ago(hours=2),
        })
    await _insert_all(mongo, "findings", findings)
    counts["findings"] = len(findings)

    # -- secrets, ports, leaks, js files, cve -------------------------------
    await _insert_all(mongo, "secrets", [{
        "tenant_id": TENANT_ID, "program_id": PROGRAM_ID,
        "fingerprint": _fp("secret", "aws"), "kind": "aws_key",
        "masked": "AKIA••••••••••••7Q3M", "value_hash": _fp("hash"),
        "location": f"https://staging.{APEX}/static/js/main.4f2a.js",
        "severity": "high", "first_seen": _ago(days=4), "last_seen": _ago(hours=2),
        "is_new": True,
    }])
    counts["secrets"] = 1

    ports = [
        ("203.0.113.14", 8080, "http", "Jetty", "9.4.51"),
        ("203.0.113.14", 50000, "jenkins-cli", "Jenkins", "2.426"),
        ("203.0.113.18", 3389, "ms-wbt-server", "Microsoft Terminal Services", ""),
        ("203.0.113.11", 443, "https", "nginx", "1.24.0"),
    ]
    await _insert_all(mongo, "ports", [{
        "tenant_id": TENANT_ID, "program_id": PROGRAM_ID,
        "fingerprint": _fp("port", ip, port), "ip": ip, "port": port, "protocol": "tcp",
        "service": svc, "product": prod, "version": ver,
        "first_seen": _ago(days=20), "last_seen": _ago(hours=2),
    } for ip, port, svc, prod, ver in ports])
    counts["ports"] = len(ports)

    await _insert_all(mongo, "leaks", [{
        "tenant_id": TENANT_ID, "program_id": PROGRAM_ID,
        "fingerprint": _fp("leak", 1), "kind": "generic_api_key",
        "masked": "sk_live_••••••••4b2f", "source": "github",
        "repo": "demo-corp/internal-scripts", "url": "https://github.com/demo-corp/internal-scripts",
        "severity": "high", "first_seen": _ago(days=9),
    }])
    counts["leaks"] = 1

    await _insert_all(mongo, "js_files", [{
        "tenant_id": TENANT_ID, "program_id": PROGRAM_ID,
        "fingerprint": _fp("js", 1), "url": f"https://staging.{APEX}/static/js/main.4f2a.js",
        "size": 482_193, "interesting_count": 34,
        "source_map": f"https://staging.{APEX}/static/js/main.4f2a.js.map",
        "hostnames": [f"api.{APEX}", f"internal-metrics.{APEX}"],
        "items": [
            {"value": "/api/internal/v2/users", "kind": "path", "tags": ["api", "internal"],
             "absolute": f"https://api.{APEX}/api/internal/v2/users"},
            {"value": "/api/internal/v2/billing", "kind": "path",
             "tags": ["api", "internal", "payment"],
             "absolute": f"https://api.{APEX}/api/internal/v2/billing"},
            {"value": "/admin/users", "kind": "path", "tags": ["admin"],
             "absolute": f"https://api.{APEX}/admin/users"},
            {"value": f"internal-metrics.{APEX}", "kind": "url", "tags": ["own-domain"],
             "absolute": None},
        ],
        "first_seen": _ago(days=6), "last_seen": _ago(hours=2),
    }])
    counts["js_files"] = 1

    await _insert_all(mongo, "cve_matches", [{
        "tenant_id": TENANT_ID, "program_id": PROGRAM_ID,
        "fingerprint": _fp("cve", "2024-23897"), "cve_id": "CVE-2024-23897",
        "asset": f"jenkins.{APEX}", "cpe": "cpe:2.3:a:jenkins:jenkins",
        "severity": "high", "cvss": 9.8, "kev": True, "confidence": "high",
        "summary": "Jenkins CLI allows arbitrary file read on the controller.",
        "first_seen": _ago(days=11), "last_seen": _ago(hours=2),
    }])
    counts["cve_matches"] = 1

    await mongo.collection("domain_intel").insert_one({
        "tenant_id": TENANT_ID, "program_id": PROGRAM_ID,
        "email": {
            "spf": "v=spf1 include:_spf.google.com ~all", "spf_present": True,
            "dmarc": None, "dmarc_present": False, "dmarc_policy": None,
            "dkim_selectors": ["google"], "spoofable": True,
        },
        "registration": {
            "registrar": "Example Registrar, Inc.",
            "created_at": _ago(days=1600).isoformat(),
            "expires_at": (NOW + timedelta(days=284)).isoformat(),
            "days_to_expiry": 284,
            "statuses": ["clientTransferProhibited"],
            "nameservers": ["ns1.example-dns.com", "ns2.example-dns.com"],
            "dnssec": False, "transfer_locked": True,
        },
        "checked_at": _ago(hours=2),
    })

    # -- deltas (the Changes tab) --------------------------------------------
    deltas = [
        ("asset_added", f"staging.{APEX}", "New subdomain appeared", "high"),
        ("finding_added", f"legacy.{APEX}", "New critical finding: exposed .git", "critical"),
        ("endpoint_added", f"api.{APEX}/graphql", "GraphQL endpoint discovered", "medium"),
        ("asset_removed", f"temp-cdn.{APEX}", "Host no longer resolves", "info"),
        ("port_opened", "203.0.113.14:50000", "Jenkins CLI port opened", "high"),
    ]
    await _insert_all(mongo, "deltas", [{
        "tenant_id": TENANT_ID, "program_id": PROGRAM_ID,
        "fingerprint": _fp("delta", i), "kind": kind, "target": target,
        "summary": summary, "severity": sev,
        "created_at": _ago(hours=(i + 1) * 5),
    } for i, (kind, target, summary, sev) in enumerate(deltas)])
    counts["deltas"] = len(deltas)

    # -- scan history + a live run with logs ---------------------------------
    runs = []
    for day in range(1, 8):
        runs.append({
            "tenant_id": TENANT_ID, "program_id": PROGRAM_ID,
            "scan_id": f"demo-full-{day}", "pipeline": "full", "status": "success",
            "started_at": _ago(days=day, minutes=40), "finished_at": _ago(days=day),
            "updated_at": _ago(days=day),
            "stages": [{"name": s, "status": "success",
                        "stats": {"found": _spread(0, 40)}} for s in STAGES],
            "stats": {"assets": 12, "findings": len(FINDINGS)}, "targets": [],
        })
    # One run in flight, so the Activity tab shows live progress + logs.
    live_at = _ago(minutes=6)
    running_index = 17  # the `scan` stage
    runs.append({
        "tenant_id": TENANT_ID, "program_id": PROGRAM_ID,
        "scan_id": "demo-full-live", "pipeline": "full", "status": "running",
        "started_at": live_at, "updated_at": _ago(seconds=20),
        "stages": [
            {"name": s,
             "status": ("success" if i < running_index
                        else "running" if i == running_index else "queued"),
             "stats": {"found": _spread(1, 30)} if i < running_index else {},
             "note": ("not enabled — needs a Shodan/Censys API key"
                      if s in ("uncover", "cloud_assets") else None)}
            for i, s in enumerate(STAGES)
        ],
        "stats": {}, "targets": [], "logs": LOG_LINES,
    })
    await _insert_all(mongo, "scan_runs", runs)
    counts["scan_runs"] = len(runs)

    for pipeline in STAGES:
        await mongo.collection("schedule").insert_one({
            "tenant_id": TENANT_ID, "program_id": PROGRAM_ID,
            "pipeline": pipeline, "last_run_at": _ago(hours=_spread(2, 30)),
        })

    return counts


async def _main(wipe: bool) -> int:  # pragma: no cover - CLI
    from db.mongo import get_mongo

    mongo = get_mongo()
    counts = await seed(mongo, wipe=wipe)
    print("demo seeded:")
    for k, v in sorted(counts.items()):
        print(f"  {k:<14} {v}")
    print(f"\n  sign in at the demo with  {DEMO_EMAIL} / {DEMO_PASSWORD}")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI
    ap = argparse.ArgumentParser(description="Seed the public read-only demo")
    ap.add_argument("--keep-existing", action="store_true", help="do not wipe first")
    args = ap.parse_args()
    raise SystemExit(asyncio.run(_main(wipe=not args.keep_existing)))
