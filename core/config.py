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

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="VANTARI_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # -- environment -----------------------------------------------------
    env: str = Field(default="dev", description="dev | staging | prod")
    debug: bool = Field(default=True)

    # -- datastore (self-hosted MongoDB by default; Atlas optional) ------
    mongo_uri: str = Field(default="mongodb://localhost:27017")
    mongo_db: str = Field(default="vantari")

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
    masscan_enabled: bool = Field(
        default=False, description="Hard-off in v1; needs dedicated netblocks (ADR-0004)"
    )

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
    email_from: str = Field(default="Vantari <no-reply@vantari.local>")
    smtp_host: str | None = Field(default=None)
    smtp_port: int = Field(default=587)
    smtp_user: str | None = Field(default=None)
    smtp_password: SecretStr | None = Field(default=None)
    smtp_starttls: bool = Field(default=True)
    app_base_url: str = Field(
        default="http://localhost:3000",
        description="Public frontend URL — used to build verification links.",
    )
    require_email_verification: bool = Field(
        default=False,
        description=(
            "When true, a program cannot be created until the owner's email is verified "
            "(§7 Phase C). Off in dev so the local flow isn't blocked; on in prod."
        ),
    )
    email_verification_ttl_seconds: int = Field(default=86400)  # 24h
    email_resend_cooloff_seconds: int = Field(default=60)

    # -- observability ---------------------------------------------------
    sentry_dsn: SecretStr | None = Field(default=None)
    metrics_enabled: bool = Field(default=True)
    # The registry is per-process and the worker/scheduler serve no HTTP, so
    # without their own listener their metrics can never be scraped.
    metrics_port: int = Field(default=9100, description="worker/scheduler /metrics port")
    log_level: str = Field(default="INFO")

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
