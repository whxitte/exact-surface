"""Request/response models for the API layer (Pydantic v2)."""

from __future__ import annotations

from pydantic import BaseModel, EmailStr, Field

from core.models import ChannelType, Role, VerificationMethod
from core.severity import Severity


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
    excluded_hosts: list[str] = Field(default_factory=list)
    excluded_cidrs: list[str] = Field(default_factory=list)


class VerifyRequestResponse(BaseModel):
    method: VerificationMethod
    token: str
    instructions: str


class VerifyCheckResponse(BaseModel):
    verified: bool
    detail: str = ""


# -- authorization -----------------------------------------------------------
class AuthorizationCreate(BaseModel):
    #: CIDRs the customer *requests* be treated as their own dedicated infra.
    #: Plain strings by design: the class/action-set/confirmed_via are decided by
    #: the server against real ASN data (§9b step 3) and can never be asserted by
    #: the client — otherwise "dedicated" would be self-granted.
    ip_scope: list[str] = Field(default_factory=list, max_length=64)
    tos_version: str = "v1"


class NotificationChannelCreate(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    type: ChannelType
    min_severity: Severity = Severity.MEDIUM
    config: dict = Field(default_factory=dict)
