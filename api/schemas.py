"""Request/response models for the API layer (Pydantic v2).

Externally-supplied values are validated here at the trust boundary via
:mod:`core.validation`, so a request crafted with curl/Burp (which ignores any
frontend check) is rejected with a 422 before anything is persisted or acted on.
"""

from __future__ import annotations

from pydantic import BaseModel, EmailStr, Field, field_validator, model_validator

from core.models import ChannelType, Role, VerificationMethod
from core.severity import Severity
from core.validation import (
    MAX_EXCLUDED_CIDRS,
    MAX_EXCLUDED_HOSTS,
    normalize_apex_domain,
    normalize_cidr,
    normalize_hostname,
    validate_email_address,
    validate_public_http_url,
    validate_telegram_chat_id,
    validate_telegram_token,
)


# -- auth --------------------------------------------------------------------
class SignupRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=200)
    tenant_name: str = Field(min_length=1, max_length=120)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class VerifyEmailRequest(BaseModel):
    token: str = Field(min_length=1, max_length=200)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"  # noqa: S105 - OAuth token type, not a secret
    tenant_id: str


class ApiKeyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    role: Role = Role.MEMBER


class ApiKeyCreated(BaseModel):
    key_id: str
    name: str
    api_key: str  # raw key — shown exactly once
    prefix: str


# -- programs ----------------------------------------------------------------
class ProgramCreate(BaseModel):
    apex_domain: str = Field(min_length=3, max_length=253)
    excluded_hosts: list[str] = Field(default_factory=list, max_length=MAX_EXCLUDED_HOSTS)
    excluded_cidrs: list[str] = Field(default_factory=list, max_length=MAX_EXCLUDED_CIDRS)

    @field_validator("apex_domain")
    @classmethod
    def _valid_domain(cls, v: str) -> str:
        # A program is a domain we will resolve and scan — reject anything that isn't a
        # plain registrable domain so a URL/IP/path can't steer scope resolution.
        return normalize_apex_domain(v)

    @field_validator("excluded_hosts")
    @classmethod
    def _valid_hosts(cls, v: list[str]) -> list[str]:
        return [normalize_hostname(h) for h in v]

    @field_validator("excluded_cidrs")
    @classmethod
    def _valid_cidrs(cls, v: list[str]) -> list[str]:
        return [normalize_cidr(c) for c in v]


class VerifyRequestResponse(BaseModel):
    method: VerificationMethod
    token: str
    instructions: str


class VerifyCheckResponse(BaseModel):
    verified: bool
    detail: str = ""


# -- authorization -----------------------------------------------------------
class AuthorizationCreate(BaseModel):
    #: CIDRs the operator *requests* be treated as their own dedicated infra.
    #: Plain strings by design: the class/action-set/confirmed_via are decided by
    #: the server against real ASN data (§9b step 3) and can never be asserted by
    #: the client — otherwise "dedicated" would be self-granted.
    ip_scope: list[str] = Field(default_factory=list, max_length=64)
    tos_version: str = Field(default="v1", max_length=32)

    @field_validator("ip_scope")
    @classmethod
    def _valid_cidrs(cls, v: list[str]) -> list[str]:
        # The server re-confirms these against real ASN data, but validate the shape at
        # the boundary so a garbage/oversized value can't be persisted as a request.
        return [normalize_cidr(c) for c in v]


class NotificationChannelCreate(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    type: ChannelType
    min_severity: Severity = Severity.MEDIUM
    config: dict = Field(default_factory=dict)

    @model_validator(mode="after")
    def _valid_config(self) -> NotificationChannelCreate:
        """Validate the per-type config the frontend can't be trusted to. A webhook URL
        is an SSRF surface (the server POSTs to it), so it must be a public http(s) URL;
        a Telegram token is validated so it can't rewrite the request host. Delivery is
        *also* guarded at send time (modules.safe_http) — this is defence in depth plus
        immediate feedback."""
        cfg = self.config or {}
        if len(cfg) > 20:
            raise ValueError("too many config fields")
        for key, val in cfg.items():
            if isinstance(val, str) and len(val) > 4096:
                raise ValueError(f"config field '{key}' is too long")
        t = self.type
        if t in (ChannelType.DISCORD, ChannelType.SLACK):
            cfg["webhook_url"] = validate_public_http_url(cfg.get("webhook_url", ""))
        elif t == ChannelType.WEBHOOK:
            cfg["url"] = validate_public_http_url(cfg.get("url", ""))
        elif t == ChannelType.TELEGRAM:
            cfg["bot_token"] = validate_telegram_token(cfg.get("bot_token", ""))
            cfg["chat_id"] = validate_telegram_chat_id(str(cfg.get("chat_id", "")))
        elif t == ChannelType.EMAIL:
            cfg["to"] = validate_email_address(cfg.get("to", ""))
        self.config = cfg
        return self
