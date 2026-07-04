"""Request/response models for the API layer (Pydantic v2)."""

from __future__ import annotations

from pydantic import BaseModel, EmailStr, Field

from core.models import IpScopeEntry, Role, VerificationMethod


# -- auth --------------------------------------------------------------------
class SignupRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=200)
    tenant_name: str = Field(min_length=1, max_length=120)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


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
    ip_scope: list[IpScopeEntry] = Field(default_factory=list)
    tos_version: str = "v1"
