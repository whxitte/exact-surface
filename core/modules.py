"""The module registry — what each stage is, what it needs, and what turning it off costs.

A user can enable or disable individual modules, but modules are not independent: the
pipeline is a chain where later stages consume what earlier ones produce. Disabling
subdomain discovery does not just skip that step — it starves probing, which starves
crawling, which starves everything after it. A toggle that silently does that is a trap.

So dependencies are declared here, in one place, and :func:`resolve` turns a user's
choices into the honest outcome: which modules will actually run, and for anything that
won't, *why* — "you turned it off" versus "it needs crawl, which is off". The UI shows
that before the user saves, and the pipeline records it as the stage's skip note.

Two modules are **essential**: ingest and probe. Everything downstream reads their
output, so they cannot be disabled — the honest answer to "can I turn off subdomain
discovery?" is "then you don't have a scanner", and it is kinder to say so in the UI
than to let someone break their deployment and wonder why nothing is found.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ModuleSpec:
    """One pipeline stage: what it does, what it needs, and how it may be controlled."""

    name: str
    label: str
    summary: str  # one line, written for the user — not the implementer
    #: modules whose output this one consumes. Empty = it only needs the domain.
    requires: tuple[str, ...] = ()
    #: on unless the user turns it off. False = opt-in (costly, noisy, or needs a key).
    default_enabled: bool = True
    #: the spine — everything downstream reads this, so it cannot be switched off.
    essential: bool = False
    #: has its own re-run cadence the user can tune.
    schedulable: bool = True
    #: why it is opt-in, shown in the UI next to the toggle.
    opt_in_reason: str = ""


#: Declaration order = pipeline execution order, so the UI can render the real chain.
MODULES: tuple[ModuleSpec, ...] = (
    ModuleSpec(
        "domain_intel",
        "Domain intelligence",
        "Email spoofability (SPF/DMARC/DKIM) and domain registration risk. Fully "
        "passive — reads DNS and the public registry, never touches your servers.",
    ),
    ModuleSpec(
        "ingest",
        "Subdomain discovery",
        "Finds your subdomains and resolves them. Everything else works from this list.",
        essential=True,
    ),
    ModuleSpec(
        "cloud_assets",
        "Cloud asset inventory",
        "Asks your own AWS/GCP/Azure/DigitalOcean accounts what they are running, so "
        "you find the load balancer or VM nobody pointed a DNS name at. Credentials "
        "stay in your deployment and are never sent anywhere.",
        default_enabled=False,
        # Deliberately NOT "set it in Settings" — unlike every other opt-in module's
        # reason string, this one is not a per-tenant API key. Cloud provider
        # credentials carry read access to a whole account, wider blast radius than a
        # Shodan/SerpAPI key, so this module was built to never let them touch the
        # database at all (modules/recon/cloudlist.py) — they live only in a file the
        # operator mounts. The Settings page has no field for this on purpose; without
        # this sentence a customer has no way to discover that from the product itself.
        opt_in_reason=(
            "set up by whoever deployed this instance, not from Settings — see "
            "CLIENT_GUIDE.md §5.9 (EXACTSURFACE_CLOUDLIST_CONFIG)"
        ),
    ),
    ModuleSpec(
        "uncover",
        "Internet-index search",
        "Looks your assets up in Shodan/Censys/Fofa to find hosts DNS never reveals.",
        default_enabled=False,
        opt_in_reason="needs a Shodan/Censys API key",
    ),
    ModuleSpec(
        "reverse_dns",
        "Reverse-DNS sweep",
        "PTR-sweeps the IP ranges confirmed to be yours, finding hosts that exist in "
        "IP space but were never published in DNS. Only runs on ASN-verified ranges.",
        requires=("ingest",),
        default_enabled=False,
        opt_in_reason="needs ASN-confirmed dedicated IP ranges; sweeps up to 8192 addresses",
    ),
    ModuleSpec(
        "probe",
        "Live-host probing",
        "Checks which hosts answer over HTTP/S and fingerprints their technology.",
        requires=("ingest",),
        essential=True,
    ),
    ModuleSpec(
        "tls",
        "TLS inspection",
        "Certificate expiry and weak TLS configuration.",
        requires=("ingest",),
        default_enabled=False,
        opt_in_reason="adds a TLS handshake per host",
    ),
    ModuleSpec(
        "takeover",
        "Subdomain takeover",
        "Dangling DNS records pointing at cloud services somebody else could claim.",
        requires=("ingest",),
    ),
    ModuleSpec(
        "crawl",
        "Crawling & archives",
        "Crawls your live sites and mines Wayback/CommonCrawl history for URLs.",
        requires=("probe",),
    ),
    ModuleSpec(
        "content_discovery",
        "Content discovery",
        "Brute-forces hidden paths and files with tech-aware wordlists.",
        requires=("probe",),
    ),
    ModuleSpec(
        "js_mine",
        "JavaScript mining",
        "Reads your own JS bundles for API routes, internal hostnames and source maps — "
        "the routes the app tells every visitor about.",
        requires=("crawl",),
    ),
    ModuleSpec(
        "api_surface",
        "API & path disclosure",
        "Reads robots.txt, sitemaps, API schemas (Swagger/OpenAPI), GraphQL "
        "introspection and .well-known — the surface each host advertises about itself.",
        requires=("probe",),
    ),
    ModuleSpec(
        "http_misconfig",
        "CORS, redirects & WAF",
        "Checks whether hosts hand data to any origin (CORS), can launder a phishing "
        "link (open redirect), and which of them sit behind a WAF.",
        requires=("probe",),
    ),
    ModuleSpec(
        "param_discovery",
        "Hidden parameters",
        "Inventories the query parameters your pages already use, and probes for "
        "undocumented ones that change how the application behaves.",
        requires=("crawl",),
        default_enabled=False,
        opt_in_reason="sends extra requests per URL to compare responses",
    ),
    ModuleSpec(
        "broken_links",
        "Broken-link hijacking",
        "Outbound links whose destination is an unregistered domain or an unclaimed "
        "social handle that an attacker could take over.",
        requires=("crawl",),
    ),
    ModuleSpec(
        "port_scan",
        "Port scanning",
        "Open ports on infrastructure you have confirmed as yours.",
        requires=("ingest",),
    ),
    ModuleSpec(
        "service_scan",
        "Service fingerprinting",
        "Identifies the software and version behind each open port.",
        requires=("port_scan",),
        default_enabled=False,
        opt_in_reason="slower, deeper probing of each open port",
    ),
    ModuleSpec(
        "scan",
        "Vulnerability scanning",
        "Runs the Nuclei template corpus against your live endpoints.",
        requires=("probe",),
    ),
    ModuleSpec(
        "secrets",
        "Exposed secrets",
        "Scans page and script bodies for leaked API keys, tokens and credentials.",
        requires=("probe",),
    ),
    ModuleSpec(
        "cve_watch",
        "CVE watch",
        "Matches known (and actively exploited) CVEs to your fingerprinted software.",
        requires=("probe",),
    ),
    ModuleSpec(
        "github_osint",
        "Public code leaks",
        "Searches public repositories for secrets tied to your domain.",
    ),
    ModuleSpec(
        "cloud_buckets",
        "Cloud storage exposure",
        "Guesses and checks S3/GCS/Azure bucket names derived from your domain.",
        default_enabled=False,
        opt_in_reason="probes ~45 third-party endpoints; name-derived attribution",
    ),
    ModuleSpec(
        "nuclei_watch",
        "New-template watch",
        "Alerts when a newly published Nuclei template starts matching your stack.",
        requires=("probe",),
        default_enabled=False,
        opt_in_reason="baselines the template set on first run",
    ),
    ModuleSpec(
        "dork",
        "Search-engine exposure",
        "Finds content of yours that search engines have indexed but shouldn't have.",
        default_enabled=False,
        opt_in_reason="needs a search API key (SerpAPI/Brave/Google CSE)",
    ),
    ModuleSpec(
        "supply_chain",
        "Dependency confusion",
        "Internal package names referenced in your public JavaScript that nobody has "
        "claimed on npm — an attacker who publishes one lands code inside your build.",
        requires=("js_mine",),
    ),
    ModuleSpec(
        "typosquat",
        "Lookalike domains",
        "Registered domains that impersonate yours to phish your staff and customers. "
        "Third-party DNS only — never contacts the lookalike host.",
        default_enabled=False,
        opt_in_reason="resolves several hundred candidate domains per run",
    ),
    ModuleSpec(
        "correlate",
        "Risk correlation",
        "Groups related findings per host into ranked attack chains.",
        schedulable=False,
    ),
    ModuleSpec(
        "notify",
        "Alerting",
        "Delivers new findings to your configured channels.",
    ),
)

BY_NAME: dict[str, ModuleSpec] = {m.name: m for m in MODULES}
MODULE_NAMES: tuple[str, ...] = tuple(m.name for m in MODULES)
ESSENTIAL: frozenset[str] = frozenset(m.name for m in MODULES if m.essential)
OPT_IN: frozenset[str] = frozenset(m.name for m in MODULES if not m.default_enabled)


def dependents_of(name: str) -> tuple[str, ...]:
    """Modules that consume *name*'s output, directly or transitively.

    This is what the UI shows before a user confirms a toggle: turning off crawl also
    costs you JavaScript mining and broken-link hijacking, and they deserve to know
    that while deciding, not afterwards.
    """
    out: set[str] = set()
    frontier = {name}
    while frontier:
        current = frontier.pop()
        for spec in MODULES:
            if current in spec.requires and spec.name not in out:
                out.add(spec.name)
                frontier.add(spec.name)
    return tuple(n for n in MODULE_NAMES if n in out)


@dataclass(frozen=True)
class ModuleState:
    """The resolved outcome of a user's choices."""

    enabled: frozenset[str]
    #: name -> human-readable reason it will not run
    skipped: dict[str, str] = field(default_factory=dict)

    def is_enabled(self, name: str) -> bool:
        return name in self.enabled

    def reason(self, name: str) -> str:
        return self.skipped.get(name, "")


def resolve(
    *,
    enabled_modules: object = (),
    disabled_modules: object = (),
    licensed_modules: object = None,
) -> ModuleState:
    """Turn a program's stored choices into what will actually run.

    ``enabled_modules`` opts *into* the modules that are off by default;
    ``disabled_modules`` opts *out of* anything else. Essential modules ignore the
    disable list. Anything whose requirement is unmet is reported as skipped with the
    dependency named, so a stage never silently does nothing.

    ``licensed_modules`` is the set of opt-in modules the subscription covers, from
    ``core.plans``. ``None`` means "no licence restriction" (dev). A module outside it
    cannot be opted into, and says so plainly — the licence gate lives here rather than
    at the API edge because this is the one function every path already goes through
    (the settings screen, the orchestrator, the scheduler and dispatch), so a new caller
    cannot forget it.
    """
    opted_in = {str(m) for m in (enabled_modules or ())}
    opted_out = {str(m) for m in (disabled_modules or ())}
    licensed = None if licensed_modules is None else {str(m) for m in licensed_modules}

    enabled: set[str] = set()
    skipped: dict[str, str] = {}

    for spec in MODULES:
        if spec.essential:
            enabled.add(spec.name)
            continue
        if spec.name in opted_out:
            skipped[spec.name] = "turned off in settings"
            continue
        if not spec.default_enabled and licensed is not None and spec.name not in licensed:
            skipped[spec.name] = "not included in your subscription"
            continue
        if not spec.default_enabled and spec.name not in opted_in:
            skipped[spec.name] = (
                f"not enabled — {spec.opt_in_reason}" if spec.opt_in_reason else "not enabled"
            )
            continue
        enabled.add(spec.name)

    # Second pass: a module whose requirement is off cannot run either. Iterate until
    # stable so a chain (crawl off → js_mine off → nothing left for broken_links) fully
    # resolves rather than only collapsing one level.
    changed = True
    while changed:
        changed = False
        for spec in MODULES:
            if spec.name not in enabled:
                continue
            missing = [r for r in spec.requires if r not in enabled]
            if missing:
                enabled.discard(spec.name)
                need = BY_NAME[missing[0]].label
                skipped[spec.name] = f"needs {need}, which is off"
                changed = True

    return ModuleState(enabled=frozenset(enabled), skipped=skipped)


def sanitize_disabled(names: object) -> list[str]:
    """Keep only real, non-essential module names — an essential module can never be
    disabled, so silently dropping it here is the single enforcement point."""
    return sorted({str(n) for n in (names or ()) if str(n) in BY_NAME and str(n) not in ESSENTIAL})


def catalogue(
    *,
    enabled_modules: object = (),
    disabled_modules: object = (),
    licensed_modules: object = None,
) -> list[dict]:
    """The full module list with each one's current state — what the settings UI renders."""
    state = resolve(
        enabled_modules=enabled_modules,
        disabled_modules=disabled_modules,
        licensed_modules=licensed_modules,
    )
    licensed = None if licensed_modules is None else {str(m) for m in licensed_modules}
    opted_out = {str(m) for m in (disabled_modules or ())}
    return [
        {
            "name": spec.name,
            "label": spec.label,
            "summary": spec.summary,
            "requires": list(spec.requires),
            "required_by": list(dependents_of(spec.name)),
            "essential": spec.essential,
            "schedulable": spec.schedulable,
            "opt_in": not spec.default_enabled,
            "opt_in_reason": spec.opt_in_reason,
            "enabled": state.is_enabled(spec.name),
            "turned_off": spec.name in opted_out,
            "skip_reason": state.reason(spec.name),
            # False = the tier does not include it, so the UI shows an upgrade prompt
            # rather than a switch that would be refused on save.
            "licensed": (
                True if licensed is None or spec.default_enabled else spec.name in licensed
            ),
        }
        for spec in MODULES
    ]
