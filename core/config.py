"""Application configuration — Pydantic Settings, ``.env``-driven.

Every tunable lives here; nothing reads ``os.environ`` directly elsewhere. Secrets
are wrapped in ``SecretStr`` so they never appear in logs or ``repr``.

Datastore note: the default ``mongo_uri`` points at a *self-hosted* MongoDB (the
compose service / a container on the VM), which is free. MongoDB Atlas is an
optional managed target, not a requirement — see ADR-0001.
"""

from __future__ import annotations

import hashlib
from functools import lru_cache

from pydantic import AliasChoices, Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="EXACTSURFACE_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # -- environment -----------------------------------------------------
    env: str = Field(default="dev", description="dev | staging | prod")
    debug: bool = Field(default=True)

    # -- datastore (self-hosted MongoDB by default; Atlas optional) ------
    mongo_uri: str = Field(default="mongodb://localhost:27017")
    mongo_db: str = Field(default="exactsurface")

    # -- redis (task queue + politeness token buckets) -------------------
    redis_uri: str = Field(default="redis://localhost:6379/0")

    # -- auth / crypto ---------------------------------------------------
    jwt_secret: SecretStr = Field(default=SecretStr("dev-insecure-change-me"))
    jwt_algorithm: str = Field(default="HS256")
    jwt_ttl_seconds: int = Field(default=3600)
    # HMAC key for hashing exposed secrets so plaintext is never stored (§9c).
    secret_hash_key: SecretStr = Field(default=SecretStr("dev-insecure-secret-hash-key"))

    # -- scanning politeness / compliance (§3.8b) ------------------------
    global_rate_per_target: float = Field(
        default=10.0, description="Max packets/requests per second per target IP"
    )
    scan_cooloff_seconds: float = Field(default=2.0)
    # Only used when the shared (Redis) rate-limit store is unreachable: each worker
    # falls back to a local bucket at 1/worker_fleet_size of the ceiling, so even if
    # the whole fleet degrades at once the aggregate stays within the cap
    # (ADR-0012). MUST be >= the real worker replica count or that guarantee is
    # void — set it when you scale workers. Default matches the Helm chart's 3.
    worker_fleet_size: int = Field(
        default=3, ge=1, description="Worker replicas; divides the local ceiling when degraded"
    )

    # Path to a cloudlist provider config (the customer writes and mounts it). Holds
    # THEIR cloud credentials and is read only by their own deployment — self-hosting is
    # what makes this acceptable to ask for at all. READ-ONLY keys are sufficient.
    cloudlist_config: str | None = Field(default=None)

    # -- scope engine ----------------------------------------------------
    scope_feed_refresh_hours: int = Field(default=24)
    lab_allow_private: bool = Field(
        default=False,
        description="DEV ONLY: allow scanning RFC1918 private IPs (e.g. a local lab VM). "
        "Refused in prod.",
    )

    # -- retention (days) ------------------------------------------------
    retention_findings_days: int = Field(default=730)
    retention_raw_scan_days: int = Field(default=90)
    retention_raw_secret_days: int = Field(default=30)  # §9c: short raw-evidence life

    # -- external API keys (all optional; features degrade if unset) -----
    shodan_api_key: SecretStr | None = Field(default=None)
    censys_api_id: SecretStr | None = Field(default=None)
    censys_api_secret: SecretStr | None = Field(default=None)
    github_token: SecretStr | None = Field(default=None)
    google_cse_key: SecretStr | None = Field(default=None)
    google_cse_cx: str | None = Field(default=None)
    brave_api_key: SecretStr | None = Field(default=None)
    serpapi_key: SecretStr | None = Field(default=None)

    # Secret scanning fetches each discovered URL's body. The cap bounds the stage's
    # runtime, but every skipped URL is a finding we can never make — so it is set high
    # and exposed here rather than buried in the module. Raise it if your surface is
    # large and the stage still finishes inside its timeout.
    secret_scan_max_urls: int = Field(default=5000, ge=100)

    # -- content discovery -----------------------------------------------
    wordlist_dir: str = Field(
        default="/opt/wordlists",
        description="Directory holding feroxbuster wordlists (installed in the image).",
    )

    # -- worker / queue --------------------------------------------------
    worker_concurrency: int = Field(default=4)
    tool_default_timeout: float = Field(default=300.0)
    scan_tool_timeout: float = Field(
        default=3600.0,
        description=(
            "Timeout for the nuclei scan specifically — it runs the full template set "
            "against every discovered URL (very slow on a big aggressive URL set). "
            "nuclei streams findings live and keeps partial results at this budget, so "
            "this bounds it rather than failing it. Kept below stage_timeout."
        ),
    )
    stage_timeout: float = Field(
        default=4200.0,
        description=(
            "Hard per-stage ceiling in the full pipeline. A stuck stage fails cleanly "
            "(TimeoutError → stage FAILED) instead of hanging the whole job. Must exceed "
            "scan_tool_timeout (the longest single-tool stage)."
        ),
    )
    worker_job_timeout: int = Field(
        default=10800,
        description=(
            "arq per-job timeout. Above the realistic sum of all full-pipeline stage "
            "budgets so stages self-bound and arq never hard-cancels a live job (a "
            "cancel would otherwise leave the run RUNNING until the reaper)."
        ),
    )

    # -- scheduler -------------------------------------------------------
    scheduler_tick_seconds: int = Field(default=60)
    scheduler_max_jobs_per_tenant: int = Field(
        default=25, description="Fairness cap: max jobs enqueued per tenant per tick"
    )
    scan_run_stale_seconds: int = Field(
        default=21600,
        description=(
            "A queued/running ScanRun older than this is treated as orphaned and reaped "
            "to FAILED. A last-resort backstop: kept above worker_job_timeout so it only "
            "fires for runs that evaded both the per-stage ceiling and arq's job timeout. "
            "A still-alive worker re-saves its final status regardless."
        ),
    )

    # -- email (transactional: verification, etc.) -----------------------
    # Provider-agnostic: "log" prints the message (dev default, no account needed);
    # "smtp" sends via any provider's SMTP creds (Resend/Brevo/SES/Postmark/Mailgun).
    email_transport: str = Field(default="log", description="log | smtp")
    email_from: str = Field(default="ExactSurface <no-reply@exactsurface.local>")
    smtp_host: str | None = Field(default=None)
    smtp_port: int = Field(default=587)
    smtp_user: str | None = Field(default=None)
    smtp_password: SecretStr | None = Field(default=None)
    smtp_starttls: bool = Field(default=True)
    app_base_url: str = Field(
        default="http://localhost:3000",
        description="Public frontend URL — used to build verification links.",
    )
    # A self-hosted deployment serves ONE organisation. The first signup bootstraps the
    # owner; after that, public signup is closed and the owner adds people via
    # Settings → members (which is also what the RBAC model expects). Leaving it open
    # would let anyone who can reach the login page create their own tenant on someone
    # else's server. Set true only for a multi-tenant/SaaS-style deployment.
    allow_public_signup: bool = Field(default=False)

    @property
    def public_signup_open(self) -> bool:
        """Whether a *second* organisation may sign itself up on this instance.

        Dev/local is open so tests and local work aren't blocked. Production is closed
        unless the operator explicitly opts in — that's the safe default for a
        single-organisation self-hosted deployment.
        """
        return self.allow_public_signup or not self.is_prod

    require_email_verification: bool = Field(
        default=False,
        description=(
            "When true, a program cannot be created until the owner's email is verified "
            "(§7 Phase C). Off in dev so the local flow isn't blocked; on in prod."
        ),
    )
    email_verification_ttl_seconds: int = Field(default=86400)  # 24h
    email_resend_cooloff_seconds: int = Field(default=60)

    # -- self-hosted subscription licensing (§ commercial) --------------
    # Enforce the signed subscription license. OFF in dev/tests so local work isn't
    # gated; ON in every customer deployment. When on and the license is missing,
    # invalid, or expired-past-grace, the instance runs READ-ONLY (fail closed).
    license_enforced: bool = Field(default=False)
    # Ed25519 PUBLIC key (PEM) that licenses are verified against. Baked into the image
    # you build; public by design (it can only verify, never mint). No default — an
    # enforced instance with no key configured fails closed to read-only.
    license_public_key: str | None = Field(default=None)
    # The signed license token itself, or a path to a file containing it. The token
    # (env) wins if both are set; the file lets ops mount a license without an env var.
    #
    # Accepts EXACTSURFACE_LICENSE as well as the prefix-derived
    # EXACTSURFACE_LICENSE_TOKEN. Every document we ship tells customers to set
    # EXACTSURFACE_LICENSE, and without this alias that variable was read by nothing:
    # the instance stayed read-only with "no license configured" while the operator
    # stared at a correctly-set environment variable. The short name is the documented
    # one, so it is the one that must work.
    license_token: str | None = Field(
        default=None,
        validation_alias=AliasChoices("EXACTSURFACE_LICENSE", "EXACTSURFACE_LICENSE_TOKEN"),
    )
    license_file: str | None = Field(default=None)
    # How often the instance re-evaluates the clock and (if configured) refreshes the
    # license from the license server. Also the clock high-water-mark cadence.
    license_check_interval_seconds: int = Field(default=3600, ge=60)
    # Optional online-refresh endpoint (hybrid model). When set, the instance periodically
    # asks it for a fresh signed license extending the paid period; empty = pure offline.
    license_refresh_url: str | None = Field(default=None)
    # License-gated update feed (vendor control plane). When set, the instance periodically
    # pulls the latest signed template/tool bundle; a lapsed subscription is refused fresh
    # detections (freshness enforcement). Empty = no auto-updates.
    update_feed_url: str | None = Field(default=None)
    # Where verified template bundles are extracted (point the scanner's templates here).
    update_templates_dir: str = Field(default="./data/nuclei-templates")
    # Deployment/build watermark stamped on exported reports + a response header, so a
    # leaked instance's output is traceable. Set per-build (e.g. the git sha or a tag).
    build_id: str = Field(default="dev")

    # -- backups (§7 Phase G, §9 retention) ------------------------------
    backup_dir: str = Field(default="./backups")
    # An age PUBLIC key (age1...). Public on purpose: this host encrypts to it and
    # cannot decrypt, so owning the scanning host does not yield the backup history.
    # Prod refuses to write a backup without it (scripts/backup.resolve_recipient).
    backup_age_recipient: str | None = Field(default=None)
    backup_retention_days: int = Field(default=30, ge=1)

    # -- scope-feed auto-update (§7 Phase G, ADR-0014) -------------------
    # The scheduler refreshes the shared Mongo copy of the CDN/cloud feed this often.
    # Provider ranges change slowly, so daily is ample; 0 disables the auto-refresh
    # (then run `python -m scripts.update_scope_feeds` by cron instead). Workers load
    # the refreshed feed on their next restart.
    scope_feed_refresh_hours: float = Field(default=24.0, ge=0)

    # -- api -------------------------------------------------------------
    # Cross-origin origins allowed in prod (comma-separated env). Empty is safe: the
    # shipped stack serves the frontend and API same-origin behind one proxy, so no
    # CORS is needed. Set this only if you deploy the API on a *different* origin than
    # the frontend — never to "*" with credentials (browsers reject it, and it would
    # let any site make authenticated calls).
    cors_allowed_origins: list[str] = Field(default_factory=list)

    # -- observability ---------------------------------------------------
    sentry_dsn: SecretStr | None = Field(default=None)
    metrics_enabled: bool = Field(default=True)
    # The registry is per-process and the worker/scheduler serve no HTTP, so
    # without their own listener their metrics can never be scraped.
    metrics_port: int = Field(default=9100, description="worker/scheduler /metrics port")
    log_level: str = Field(default="INFO")

    @field_validator("license_public_key")
    @classmethod
    def _accept_base64_public_key(cls, v: str | None) -> str | None:
        """Accept the verify key as a PEM *or* as base64 of a PEM.

        A PEM is multi-line, and the two channels that carry this value into an image
        are both single-line-only:

        * ``build-args:`` in docker/build-push-action is a newline-delimited KEY=VALUE
          list, so a PEM silently truncates to ``-----BEGIN PUBLIC KEY-----`` and every
          licence fails to verify -- an instance that enforces but can never be
          licensed. This shipped in v1.0.0 and was invisible in local builds, where
          compose's `args:` mapping handles newlines correctly.
        * ``.env`` has no multi-line syntax either.

        Rather than require operators to remember which channel mangles what, take
        base64 as well and normalise here.
        """
        if not v:
            return v
        text = v.strip()
        if "BEGIN" in text and "END" in text:
            return text  # already a well-formed PEM
        import base64
        import binascii

        try:
            decoded = base64.b64decode(text, validate=True).decode("utf-8").strip()
        except (binascii.Error, UnicodeDecodeError, ValueError):
            return text  # not base64 either; let verification report it
        return decoded if "BEGIN" in decoded else text

    @field_validator("env")
    @classmethod
    def _known_env(cls, v: str) -> str:
        if v not in {"dev", "staging", "prod"}:
            raise ValueError("env must be one of dev|staging|prod")
        return v

    @field_validator("email_transport")
    @classmethod
    def _known_email_transport(cls, v: str) -> str:
        if v not in {"log", "smtp"}:
            raise ValueError("email_transport must be one of log|smtp")
        return v

    @property
    def is_prod(self) -> bool:
        return self.env == "prod"

    def secret_hash_key_bytes(self) -> bytes:
        """Return the HMAC key as bytes for ``core.hashing.keyed_hash``."""
        return hashlib.sha256(self.secret_hash_key.get_secret_value().encode("utf-8")).digest()

    def assert_prod_safe(self) -> None:
        """Fail fast if prod is running with insecure development defaults."""
        if not self.is_prod:
            return
        insecure = {
            "jwt_secret": self.jwt_secret.get_secret_value().startswith("dev-insecure"),
            "secret_hash_key": self.secret_hash_key.get_secret_value().startswith("dev-insecure"),
        }
        bad = [k for k, v in insecure.items() if v]
        if bad:
            from core.errors import ConfigError

            raise ConfigError(f"insecure default(s) in prod: {', '.join(bad)}")
        if self.lab_allow_private:
            from core.errors import ConfigError

            raise ConfigError("lab_allow_private must never be enabled in prod")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Process-wide settings singleton."""
    return Settings()
