"""Auth routes: signup, login, current principal, API-key issuance."""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status

from api.auth import create_access_token, generate_api_key, hash_password, verify_password
from api.deps import Principal, get_mongo_dep, get_principal
from api.rate_limit import limiter
from api.schemas import ApiKeyCreate, ApiKeyCreated, LoginRequest, SignupRequest, TokenResponse
from core.models import ApiKey, Role, Tenant, User
from db.apikeys import ApiKeyRepo
from db.tenants import TenantRepo
from db.users import UserRepo

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/signup", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("60/minute")
async def signup(
    request: Request, body: SignupRequest, mongo: Any = Depends(get_mongo_dep)
) -> TokenResponse:
    users = UserRepo.from_mongo(mongo)
    if await users.get_by_email(body.email):
        raise HTTPException(status.HTTP_409_CONFLICT, "email already registered")

    tenant_id = "t_" + uuid.uuid4().hex[:12]
    user_id = "u_" + uuid.uuid4().hex[:12]
    await TenantRepo.from_mongo(mongo).create(Tenant(tenant_id=tenant_id, name=body.tenant_name))
    await users.create(
        User(
            tenant_id=tenant_id,
            user_id=user_id,
            email=body.email,
            password_hash=hash_password(body.password),
            role=Role.OWNER,
        )
    )
    token = create_access_token(user_id=user_id, tenant_id=tenant_id, role=Role.OWNER.value)
    return TokenResponse(access_token=token, tenant_id=tenant_id)


@router.post("/login", response_model=TokenResponse)
@limiter.limit("60/minute")
async def login(
    request: Request, body: LoginRequest, mongo: Any = Depends(get_mongo_dep)
) -> TokenResponse:
    doc = await UserRepo.from_mongo(mongo).get_by_email(body.email)
    if not doc or not verify_password(body.password, doc["password_hash"]):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")
    token = create_access_token(
        user_id=doc["user_id"], tenant_id=doc["tenant_id"], role=doc.get("role", "owner")
    )
    return TokenResponse(access_token=token, tenant_id=doc["tenant_id"])


@router.get("/me")
async def me(principal: Principal = Depends(get_principal)) -> dict:
    return {
        "tenant_id": principal.tenant_id,
        "user_id": principal.user_id,
        "role": principal.role.value,
        "auth": principal.method,
    }


@router.post("/api-keys", response_model=ApiKeyCreated, status_code=status.HTTP_201_CREATED)
async def create_api_key(
    body: ApiKeyCreate,
    principal: Principal = Depends(get_principal),
    mongo: Any = Depends(get_mongo_dep),
) -> ApiKeyCreated:
    raw, key_hash, prefix = generate_api_key()
    key_id = "k_" + uuid.uuid4().hex[:12]
    await ApiKeyRepo.from_mongo(mongo).create(
        ApiKey(
            tenant_id=principal.tenant_id,
            key_id=key_id,
            name=body.name,
            key_hash=key_hash,
            prefix=prefix,
            role=body.role,
            created_by=principal.user_id,
        )
    )
    # The raw key is returned exactly once and never stored (§9).
    return ApiKeyCreated(key_id=key_id, name=body.name, api_key=raw, prefix=prefix)
