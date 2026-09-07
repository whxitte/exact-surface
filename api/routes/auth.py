"""Auth routes: signup, login, current principal, API-key issuance."""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status

from api.auth import create_access_token, generate_api_key, hash_password, verify_password
from api.deps import (
    Principal,
    get_email_sender_dep,
    get_mongo_dep,
    get_principal,
    require_permission,
)
from api.rate_limit import limiter
from api.schemas import (
    ApiKeyCreate,
    ApiKeyCreated,
    LoginRequest,
    SignupRequest,
    TokenResponse,
    VerifyEmailRequest,
)
from core.config import get_settings
from core.email import EmailSender, build_verification_email
from core.logging import logger
from core.models import ApiKey, Group, Role, Tenant, User
from core.permissions import DEFAULT_VIEWER_PERMISSIONS, SETTINGS_MANAGE
from db.apikeys import ApiKeyRepo
from db.groups import GroupRepo
from db.tenants import TenantRepo
from db.users import UserRepo

router = APIRouter(prefix="/auth", tags=["auth"])

# Bound once (not per-request) so it can be a plain dependency — the auth router is
# ungated, so key issuance carries its own SETTINGS_MANAGE guard.
_require_settings_manage = require_permission(SETTINGS_MANAGE)


async def _issue_and_send_verification(
    mongo: Any, sender: EmailSender, *, user_id: str, email: str
) -> None:
    """Mint a one-time token, persist it, and send the verification email.
    Best-effort: a send failure is logged, never raised (signup must not fail on
    email). The log transport always succeeds in dev."""
    settings = get_settings()
    token = secrets.token_urlsafe(32)
    now = datetime.now(UTC)
    exp = now + timedelta(seconds=settings.email_verification_ttl_seconds)
    await UserRepo.from_mongo(mongo).set_verification(
        user_id, token=token, expires_at=exp, sent_at=now
    )
    link = f"{settings.app_base_url.rstrip('/')}/verify-email?token={token}"
    try:
        await sender.send(build_verification_email(to=email, link=link))
    except Exception as exc:  # noqa: BLE001 - defensive; senders already swallow errors
        logger.warning("verification email to {} not sent: {}", email, type(exc).__name__)


@router.get("/signup-open")
async def signup_open(mongo: Any = Depends(get_mongo_dep)) -> dict:
    """Whether /auth/signup will currently accept a new tenant.

    Unauthenticated on purpose — the login page calls this to decide whether to show
    "Create one" at all. Without it the link was unconditional: on any instance past
    its first account, clicking it walked an operator through a full signup form only
    to fail at submission with a 403. The signup endpoint's own check
    (self.count() > 0 and not public_signup_open) is unchanged and remains the actual
    enforcement — this only mirrors that decision so the UI can match reality instead
    of a raw boolean and a count().
    """
    open_ = get_settings().public_signup_open or await TenantRepo.from_mongo(mongo).count() == 0
    return {"open": open_}


@router.post("/signup", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("60/minute")
async def signup(
    request: Request,
    body: SignupRequest,
    mongo: Any = Depends(get_mongo_dep),
    sender: EmailSender = Depends(get_email_sender_dep),
) -> TokenResponse:
    users = UserRepo.from_mongo(mongo)
    if await users.get_by_email(body.email):
        raise HTTPException(status.HTTP_409_CONFLICT, "email already registered")

    # Self-hosted instances serve one organisation. The first signup bootstraps the
    # owner; after that public signup is closed, so someone who merely reaches this
    # instance cannot create their own tenant on the operator's server. Additional
    # people are added by the owner under Settings → members.
    tenants = TenantRepo.from_mongo(mongo)
    if not get_settings().public_signup_open and await tenants.count() > 0:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "this instance is already set up — ask its owner to add you under Settings → members",
        )

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
    # Seed the read-only "Viewer" group so the owner has a sane default to assign new
    # users to (§ access control). It can be renamed/re-permissioned but not deleted.
    await GroupRepo.from_mongo(mongo).save(
        Group(
            tenant_id=tenant_id,
            group_id="g_" + uuid.uuid4().hex[:12],
            name="Viewer",
            permissions=sorted(DEFAULT_VIEWER_PERMISSIONS),
            is_default=True,
        )
    )
    await _issue_and_send_verification(mongo, sender, user_id=user_id, email=body.email.lower())
    token = create_access_token(user_id=user_id, tenant_id=tenant_id, role=Role.OWNER.value)
    return TokenResponse(access_token=token, tenant_id=tenant_id)


@router.post("/verify-email")
async def verify_email(body: VerifyEmailRequest, mongo: Any = Depends(get_mongo_dep)) -> dict:
    """Consume a verification token (from the emailed link). One-time: a used or
    expired token returns 400 so a stale link can't silently 're-verify'."""
    doc = await UserRepo.from_mongo(mongo).verify_by_token(body.token, now=datetime.now(UTC))
    if not doc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid or expired verification token")
    return {"verified": True, "email": doc["email"]}


@router.post("/resend-verification", status_code=status.HTTP_204_NO_CONTENT)
@limiter.limit("10/minute")
async def resend_verification(
    request: Request,
    principal: Principal = Depends(get_principal),
    mongo: Any = Depends(get_mongo_dep),
    sender: EmailSender = Depends(get_email_sender_dep),
) -> None:
    if not principal.user_id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "no user to verify")
    user = await UserRepo.from_mongo(mongo).get_by_id(principal.user_id)
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    if user.get("email_verified"):
        return  # already verified — a harmless no-op
    # Per-user cool-off so the endpoint can't be used to spam someone's inbox.
    last = user.get("verification_sent_at")
    now = datetime.now(UTC)
    cooloff = get_settings().email_resend_cooloff_seconds
    if last is not None and (now - last).total_seconds() < cooloff:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "please wait before resending")
    await _issue_and_send_verification(mongo, sender, user_id=user["user_id"], email=user["email"])


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
async def me(
    principal: Principal = Depends(get_principal), mongo: Any = Depends(get_mongo_dep)
) -> dict:
    email_verified: bool | None = None
    email: str | None = None
    if principal.user_id:
        user = await UserRepo.from_mongo(mongo).get_by_id(principal.user_id)
        if user:
            email_verified = bool(user.get("email_verified"))
            email = user.get("email")

    return {
        "tenant_id": principal.tenant_id,
        "user_id": principal.user_id,
        "role": principal.role.value,
        "auth": principal.method,
        "email": email,
        "email_verified": email_verified,
        # Effective RBAC state so the UI can hide what the caller can't do (§ access
        # control). Authoritative enforcement is server-side; this is only for display.
        "is_owner": principal.is_owner,
        "permissions": sorted(principal.permissions),
    }


@router.post("/api-keys", response_model=ApiKeyCreated, status_code=status.HTTP_201_CREATED)
async def create_api_key(
    body: ApiKeyCreate,
    principal: Principal = Depends(_require_settings_manage),
    mongo: Any = Depends(get_mongo_dep),
) -> ApiKeyCreated:
    # The API router is ungated (login/me must stay open), so this route carries its
    # own SETTINGS_MANAGE guard. A key acts with its creator's *live* permissions
    # (resolved via created_by on every request), so a non-owner's key is naturally
    # bounded to what that member can do — and this check stops it being minted with a
    # higher role than the creator holds.
    if body.role == Role.OWNER and principal.role != Role.OWNER:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "cannot mint a key above your own role")
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
