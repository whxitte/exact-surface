"""All Pydantic v2 domain models. Every model is tenant-scoped (§3.4, §5).

Two base classes:

* :class:`TenantScopedModel` — the root every persisted model extends; carries
  ``tenant_id`` + timestamps.
* :class:`StatefulModel` — extends the root for *observed* entities (assets,
  endpoints, ports, findings, ...) that need state-awareness: ``program_id``,
  a stable ``fingerprint`` (the idempotent upsert key), and
  ``first_seen`` / ``last_seen`` / ``is_new`` bookkeeping.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from core.lifecycle import FindingState
from core.severity import Severity


def _utcnow() -> datetime:
    return datetime.now(UTC)


class TenantScopedModel(BaseModel):
    """Root of every persisted model. No document exists without a tenant."""

    model_config = ConfigDict(use_enum_values=False, extra="ignore")

    tenant_id: str = Field(..., description="Tenant this record belongs to")
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)


class StatefulModel(TenantScopedModel):
    """Base for state-aware, deduplicated observations."""

    program_id: str = Field(..., description="Program (domain) this belongs to")
    fingerprint: str = Field(..., description="Stable content hash; the upsert key")
    first_seen: datetime = Field(default_factory=_utcnow)
    last_seen: datetime = Field(default_factory=_utcnow)
    is_new: bool = Field(default=True, description="True exactly once per genuine insert")


# --------------------------------------------------------------------------- #
# Tenancy / accounts
# --------------------------------------------------------------------------- #
class Plan(str, Enum):
    FREE = "free"
    PRO = "pro"
    BUSINESS = "business"
    ENTERPRISE = "enterprise"


class Tenant(BaseModel):
    model_config = ConfigDict(extra="ignore")

    tenant_id: str
    name: str
    plan: Plan = Plan.FREE
    #: account-wide per-pipeline cadence defaults (seconds); a program's own
    #: cadence_overrides win over these. See taskqueue.cadence.effective_cadence.
    cadence_overrides: dict[str, int] = Field(default_factory=dict)
    #: account-wide per-stage timeout defaults (seconds); a program's own
    #: timeout_overrides win. See taskqueue.timeouts.effective_timeouts.
    timeout_overrides: dict[str, int] = Field(default_factory=dict)
    #: account-wide alert-policy defaults; a program's own alert_policy wins.
    #: See core.alert_policy.effective_alert_policy.
    alert_policy: dict = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)


class Role(str, Enum):
    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"


class User(TenantScopedModel):
    """An account. Email is globally unique; the owner is created at signup."""

    user_id: str
    email: str
    password_hash: str
    role: Role = Role.OWNER
    email_verified: bool = False
    # One-time verification token (random, hashed at rest would be ideal; kept opaque
    # and cleared on use). ``verification_expires_at`` bounds its life; ``…_sent_at``
    # rate-limits resend.
    verification_token: str | None = None
    verification_expires_at: datetime | None = None
    verification_sent_at: datetime | None = None


class ApiKey(TenantScopedModel):
    """A per-tenant API key. Only the SHA-256 hash is stored; raw shown once (§9)."""

    key_id: str
    name: str
    key_hash: str
    prefix: str  # first chars of the raw key, for display/identification
    role: Role = Role.MEMBER
    created_by: str | None = None
    last_used_at: datetime | None = None


class ChannelType(str, Enum):
    DISCORD = "discord"
    SLACK = "slack"
    TELEGRAM = "telegram"
    EMAIL = "email"
    WEBHOOK = "webhook"


class NotificationChannel(TenantScopedModel):
    """A per-tenant alert destination with a severity threshold (§module 34-38)."""

    channel_id: str
    name: str
    type: ChannelType
    enabled: bool = True
    min_severity: Severity = Severity.MEDIUM
    # Channel-specific: {webhook_url} | {bot_token, chat_id} | {host, port, user, ...}
    config: dict = Field(default_factory=dict)


class VerificationMethod(str, Enum):
    DNS_TXT = "dns_txt"
    HTTP_FILE = "http_file"


class Program(TenantScopedModel):
    """A verified domain a tenant has asked Vantari to monitor."""

    program_id: str
    apex_domain: str
    verified: bool = False
    verification_method: VerificationMethod | None = None
    verification_token: str | None = None
    excluded_hosts: list[str] = Field(default_factory=list)
    excluded_cidrs: list[str] = Field(default_factory=list)
    enabled: bool = True
    #: §9b opt-in: customer attests they own the cloud infra their domain runs on,
    #: unlocking port/content/active scans on cloud/public IPs (not third-party CDNs).
    scan_shared_infra: bool = False
    #: optional modules turned on for this program (see orchestrate.OPTIONAL_MODULES);
    #: disabled ones render as a gray node and do no work.
    enabled_modules: list[str] = Field(default_factory=list)
    #: nuclei template ids relevant to this program's fingerprinted tech, as of the
    #: last watch run (module 22). ``None`` = never baselined. Only *relevant* ids are
    #: stored (tens), never the full ~10k corpus. See pipelines/nuclei_watch.py.
    known_template_ids: list[str] | None = None
    #: per-pipeline cadence overrides (seconds) for THIS program; falls back to the
    #: tenant defaults, then the built-ins. See taskqueue.cadence.effective_cadence.
    cadence_overrides: dict[str, int] = Field(default_factory=dict)
    #: per-stage max-runtime overrides (seconds); same precedence as cadence.
    #: See taskqueue.timeouts.effective_timeouts.
    timeout_overrides: dict[str, int] = Field(default_factory=dict)
    #: partial alert-policy overrides for THIS program; falls back to tenant defaults,
    #: then the built-ins. See core.alert_policy.effective_alert_policy.
    alert_policy: dict = Field(default_factory=dict)
    #: set once the first full pipeline run completes — until then the scheduler
    #: bootstraps a single ordered full run instead of fanning out per-phase.
    initial_scan_completed_at: datetime | None = None


class IpScopeEntry(BaseModel):
    cidr: str
    ip_class: str  # mirrors core.scope.IpClass value
    action_set: list[str]
    confirmed_via: str  # e.g. "whois:AS14061" or "acknowledged_shared"


class Authorization(TenantScopedModel):
    """Per-program authorization-to-scan artifact (§5d, §9b, §9e).

    No pipeline runs without a current, valid record for the program. This is the
    legal-defensibility artifact and the source of ``authorized_dedicated_cidrs``.
    """

    program_id: str
    authorized_by: str  # actor id
    authorized_at: datetime = Field(default_factory=_utcnow)
    apex_verified: bool = False
    verification_method: VerificationMethod | None = None
    ip_scope: list[IpScopeEntry] = Field(default_factory=list)
    tos_version: str = "v1"
    revoked: bool = False

    def is_current(self) -> bool:
        return self.apex_verified and not self.revoked


# --------------------------------------------------------------------------- #
# Observed entities
# --------------------------------------------------------------------------- #
class Asset(StatefulModel):
    """A discovered host (subdomain / apex)."""

    hostname: str
    resolved_ips: list[str] = Field(default_factory=list)
    ip_class: str | None = None  # last-classified (core.scope.IpClass value)
    source: str = "unknown"  # discovering module, e.g. "subfinder"
    is_ephemeral: bool = False  # preview/staging env (§module 19)
    #: full DNS records (A/AAAA/CNAME/NS/MX/TXT) from dnsx recon — CNAMEs reveal
    #: cloud services / takeover candidates. {record_type: [values]}.
    dns_records: dict[str, list[str]] = Field(default_factory=dict)
    #: service name if this host is a likely subdomain-takeover target (dangling
    #: CNAME), else None. Set by the takeover stage; re-evaluated each scan.
    takeover_risk: str | None = None
    #: User can mute an individual asset — unmonitored hosts are skipped by crawl /
    #: content-discovery / port-scan. Preserved across re-scans (see AssetRepo).
    monitored: bool = True


class Endpoint(StatefulModel):
    """An alive HTTP endpoint with a light fingerprint."""

    url: str
    method: str = "GET"
    status_code: int | None = None
    title: str | None = None
    tech: list[str] = Field(default_factory=list)
    source: str = ""  # discovering module: probe | crawl | feroxbuster
    content_hash: str | None = None  # body/title hash for delta detection
    #: risk categories from core.endpoint_risk (admin/api/idor/ssrf/payment/…) —
    #: which of the crawled URLs are worth a human's attention.
    risk_tags: list[str] = Field(default_factory=list)


class Port(StatefulModel):
    """An open port + service banner on an IP."""

    ip: str
    port: int
    protocol: str = "tcp"
    service: str | None = None
    product: str | None = None
    version: str | None = None


class Finding(StatefulModel):
    """A vulnerability / exposure finding from any scanning module."""

    check_id: str  # nuclei template id or internal check name
    module: str
    location: str  # matched URL / IP
    locator: str = ""  # discriminator (param name, secret key, ...)
    name: str
    description: str = ""
    severity: Severity = Severity.INFO
    state: FindingState = FindingState.NEW
    cvss: float | None = None
    references: list[str] = Field(default_factory=list)
    reproduction: str | None = None  # attacker-perspective repro command
    raw: dict = Field(default_factory=dict)  # tool output; retention-limited


class ExposedSecret(StatefulModel):
    """A leaked secret — plaintext is NEVER stored (§9c).

    ``masked`` shows a safe hint (``AKIA••••7Q``); ``value_hash`` is the keyed hash
    used for dedup; ``encrypted_snippet`` (if retained) is envelope-encrypted and
    purged after ``retention_raw_secret_days``.
    """

    kind: str  # aws_key, github_pat, private_key, generic_api_key, ...
    masked: str
    value_hash: str
    source_locator: str  # URL/file:line where it was found
    severity: Severity = Severity.HIGH
    state: FindingState = FindingState.NEW
    encrypted_snippet: str | None = None


class Leak(StatefulModel):
    """A secret leaked in public source (GitHub etc.) — masked, never plaintext (§9c)."""

    kind: str
    masked: str
    value_hash: str
    source: str = "github"
    repo: str | None = None
    file_path: str | None = None
    url: str | None = None
    severity: Severity = Severity.HIGH
    state: FindingState = FindingState.NEW


class CveMatch(StatefulModel):
    """A CVE matched to a fingerprinted asset, with match confidence (§module 21)."""

    cve_id: str
    cpe: str
    asset_fingerprint: str
    cvss: float | None = None
    on_kev: bool = False
    confidence: str = "low"  # low | medium | high
    severity: Severity = Severity.INFO
    state: FindingState = FindingState.NEW


class DeltaKind(str, Enum):
    STATUS_CHANGE = "status_change"
    TITLE_CHANGE = "title_change"
    TECH_CHANGE = "tech_change"
    CERT_CHANGE = "cert_change"
    NEW_PORT = "new_port"
    NEW_ASSET = "new_asset"


class Delta(TenantScopedModel):
    """An observed change to an asset over time (§module 23)."""

    program_id: str
    asset_fingerprint: str
    kind: DeltaKind
    before: str | None = None
    after: str | None = None
    observed_at: datetime = Field(default_factory=_utcnow)


class ScanStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"  # e.g. state-aware no-op or out-of-scope


class ScanStage(BaseModel):
    """One stage of a multi-stage run (ingest→probe→crawl→scan→secrets).

    Persisted inside :class:`ScanRun.stages` and rewritten as the pipeline
    advances, so the activity feed renders a live queued→running→done stepper.
    """

    name: str
    status: ScanStatus = ScanStatus.QUEUED
    started_at: datetime | None = None
    finished_at: datetime | None = None
    stats: dict = Field(default_factory=dict)
    note: str | None = None  # why skipped, or a short human explanation


class ScanRun(TenantScopedModel):
    """Audit record of one pipeline execution."""

    scan_id: str
    program_id: str
    pipeline: str
    status: ScanStatus = ScanStatus.QUEUED
    started_at: datetime | None = None
    finished_at: datetime | None = None
    stats: dict = Field(default_factory=dict)  # counts: discovered/new/errors
    stages: list[ScanStage] = Field(default_factory=list)  # per-stage progress (full runs)
    #: cascade/target-scoped runs carry the hostnames they were limited to; empty means
    #: full coverage (scheduled or full run). Load-bearing for gone-detection: only
    #: full-coverage runs are evidence that a missing item is actually gone.
    targets: list[str] = Field(default_factory=list)
    note: str | None = None  # why skipped / short explanation (single-pipeline runs)
    error: str | None = None
