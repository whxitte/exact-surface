"""Shared API dependencies: principal resolution + tenant-ownership guards (§3.7).

Tenant isolation is enforced *here*, centrally: every data route depends on
``require_program`` (or filters by ``principal.tenant_id``), so a valid token for
tenant A can never reach tenant B's data even by guessing a program id — the
lookup is scoped to the caller's tenant and returns 404 for anything else.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from fastapi import Depends, Header, HTTPException, Request, status

from api.auth import InvalidToken, decode_token, hash_api_key
from core.config import get_settings
from core.email import EmailSender, get_email_sender
from core.models import Role
from core.permissions import DEFAULT_KEY_SCOPES, normalise_scopes
from core.verification import DomainVerifier
from db.apikeys import ApiKeyRepo
from db.mongo import get_mongo
from db.programs import ProgramRepo
from db.users import UserRepo

_domain_verifier = DomainVerifier()


async def get_domain_verifier() -> DomainVerifier:
    """The domain verifier. Overridden in tests to avoid real DNS/HTTP."""
    return _domain_verifier


async def get_email_sender_dep() -> EmailSender:
    """The transactional-email sender. Overridden in tests to capture messages."""
    return get_email_sender()


@dataclass(frozen=True)
class Principal:
    tenant_id: str
    user_id: str | None
    role: Role
    method: str  # "jwt" | "apikey"
    #: Effective RBAC permissions (§ access control). Owner ⇒ every permission; a
    #: non-owner ⇒ the union of their groups', empty if they have none.
    permissions: frozenset[str] = frozenset()
    #: For an API key: the scopes it was minted with, bounded by the creator's live
    #: permissions. ``None`` for an interactive session, which is not scope-limited —
    #: a person is governed by RBAC alone. See core.permissions.SCOPE_CATALOGUE.
    scopes: frozenset[str] | None = None
    key_id: str | None = None

    @property
    def is_owner(self) -> bool:
        return self.role == Role.OWNER

    @property
    def is_human(self) -> bool:
        return self.method == "jwt"

    def has(self, perm: str) -> bool:
        return perm in self.permissions

    def may(self, scope: str) -> bool:
        """Scope check. Always true for a person; for a key, the scope must be held."""
        return self.scopes is None or scope in self.scopes


async def get_mongo_dep() -> Any:
    """The Mongo handle. Overridden in tests via ``app.dependency_overrides``."""
    return get_mongo()


def clean_doc(doc: dict | None) -> dict | None:
    """Drop Mongo's ``_id`` so documents are JSON-serialisable in responses."""
    if doc is None:
        return None
    return {k: v for k, v in doc.items() if k != "_id"}


async def get_principal(
    request: Request,
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None),
    mongo: Any = Depends(get_mongo_dep),
) -> Principal:
    principal = await _resolve_principal(authorization, x_api_key, mongo)
    # Left on the request for the audit middleware, which runs after the route and
    # would otherwise have no idea who acted.
    request.state.principal = principal
    return principal


async def _resolve_principal(
    authorization: str | None, x_api_key: str | None, mongo: Any
) -> Principal:
    if authorization and authorization.startswith("Bearer "):
        try:
            payload = decode_token(authorization[7:])
        except InvalidToken as exc:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid token") from exc
        role = Role(payload.get("role", "member"))
        tenant_id = payload["tenant_id"]
        user_id = payload.get("sub")
        # Resolve permissions from the DB on every request, NOT from the token — so an
        # owner removing a user from a group takes effect immediately, not on the next
        # login. The permission set is intentionally not carried in the JWT.
        perms = await _resolve_permissions(mongo, tenant_id, user_id, role)
        return Principal(
            tenant_id=tenant_id, user_id=user_id, role=role, method="jwt", permissions=perms
        )

    if x_api_key:
        keys = ApiKeyRepo.from_mongo(mongo)
        doc = await keys.get_by_hash(hash_api_key(x_api_key))
        if not doc or doc.get("revoked_at") is not None:
            # Same message for unknown and revoked: a caller probing keys learns nothing.
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid api key")
        role = Role(doc.get("role", "member"))
        # An API key acts with its creator's current permissions (owner-created key ⇒
        # full access), resolved live so revoking the creator's access revokes the key.
        # Its scopes then narrow that: re-bounded here, not just at creation, so a
        # creator who has since lost a permission takes the key's matching scope with
        # them.
        perms = await _resolve_permissions(mongo, doc["tenant_id"], doc.get("created_by"), role)
        scopes = normalise_scopes(doc.get("scopes") or DEFAULT_KEY_SCOPES, perms)
        await keys.touch(doc["tenant_id"], doc["key_id"])
        return Principal(
            tenant_id=doc["tenant_id"],
            user_id=doc.get("created_by"),
            role=role,
            method="apikey",
            permissions=perms,
            scopes=scopes,
            key_id=doc.get("key_id"),
        )

    raise HTTPException(
        status.HTTP_401_UNAUTHORIZED,
        "missing credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def _resolve_permissions(
    mongo: Any, tenant_id: str, user_id: str | None, role: Role
) -> frozenset[str]:
    """Effective permissions for a principal — owner=all, else the union of the
    user's groups. Resolved from the DB so access changes take effect at once.

    Owner-ness and group membership are read from the live user record, not the
    caller-supplied ``role``: this makes an API key inherit its *creator's* current
    permissions (an owner-created key ⇒ full access; a member-created key is bounded
    to that member, and revoking the member revokes the key). ``role`` is only a
    fallback when there is no user record (e.g. a legacy key without ``created_by``).
    """
    from core.permissions import effective_permissions
    from db.groups import GroupRepo

    is_owner = role == Role.OWNER
    group_ids: list[str] = []
    if user_id:
        user = await UserRepo.from_mongo(mongo).get(tenant_id, user_id)
        if user:
            is_owner = user.get("role") == Role.OWNER.value
            group_ids = user.get("group_ids") or []
    if is_owner:
        return effective_permissions(is_owner=True, group_permissions=())
    perms = await GroupRepo.from_mongo(mongo).permissions_for_ids(tenant_id, group_ids)
    return effective_permissions(is_owner=False, group_permissions=perms)


def require_permission(perm: str):
    """Guard: the principal must hold *perm* (owner always does). Returns the
    principal so the route can reuse it."""

    async def _dep(principal: Principal = Depends(get_principal)) -> Principal:
        if not principal.has(perm):
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"missing permission: {perm}")
        return principal

    return _dep


def require_role(*allowed: Role):
    async def _dep(principal: Principal = Depends(get_principal)) -> Principal:
        if principal.role not in allowed:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "insufficient role")
        return principal

    return _dep


# Managing users/groups is owner-only and non-delegable (core.permissions): only a
# real OWNER may do it, so no member can ever escalate the tenant.
require_owner = require_role(Role.OWNER)

_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def require_router_access(write_permission: str):
    """Router-level RBAC gate, applied once per data router at include time.

    Every route needs :data:`~core.permissions.VIEW`; any mutating request (non-GET)
    additionally needs *write_permission*. Enforcing it here — not per route — means a
    newly-added endpoint is protected by default and no write can slip through
    unguarded. Owner holds all permissions, so this is transparent to owners.
    """
    from core.permissions import VIEW

    async def _dep(request: Request, principal: Principal = Depends(get_principal)) -> Principal:
        if not principal.has(VIEW):
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"missing permission: {VIEW}")
        if request.method not in _SAFE_METHODS and not principal.has(write_permission):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN, f"missing permission: {write_permission}"
            )
        return principal

    return _dep


async def require_verified_email(
    principal: Principal = Depends(get_principal),
    mongo: Any = Depends(get_mongo_dep),
) -> Principal:
    """Gate an action on the caller's email being verified — but only when
    ``require_email_verification`` is configured on (off in dev). API-key callers
    are exempt (keys are minted by an already-authenticated owner)."""
    if not get_settings().require_email_verification or principal.method == "apikey":
        return principal
    if principal.user_id:
        user = await UserRepo.from_mongo(mongo).get_by_id(principal.user_id)
        if user and user.get("email_verified"):
            return principal
    raise HTTPException(
        status.HTTP_403_FORBIDDEN, "verify your email address to perform this action"
    )


async def require_program(
    program_id: str,
    principal: Principal = Depends(get_principal),
    mongo: Any = Depends(get_mongo_dep),
) -> dict:
    """Return the program IFF it belongs to the caller's tenant, else 404.

    This is the tenant-isolation choke point for every program-scoped route.
    """
    program = await ProgramRepo.from_mongo(mongo).get(principal.tenant_id, program_id)
    if not program:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "program not found")
    return program


# --------------------------------------------------------------------------- #
# Guards for non-human callers
# --------------------------------------------------------------------------- #
def require_scope(scope: str):
    """A route an API key may only call with *scope*. Interactive sessions pass; they
    are governed by RBAC, which every route already applies."""

    async def _dep(principal: Principal = Depends(get_principal)) -> Principal:
        if not principal.may(scope):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"this API key does not have the '{scope}' scope",
            )
        return principal

    return _dep


def writes_require_scope(scope: str):
    """Router-level form of :func:`require_scope`: applies to POST/PUT/PATCH/DELETE
    only, so a router whose reads are covered by ``read`` needs one line, not one per
    route."""

    async def _dep(request: Request, principal: Principal = Depends(get_principal)) -> Principal:
        if request.method in _MUTATING and not principal.may(scope):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"this API key does not have the '{scope}' scope",
            )
        return principal

    return _dep


async def require_human(principal: Principal = Depends(get_principal)) -> Principal:
    """Refuse API keys outright, whatever their scopes.

    The actions behind this either widen what may be scanned (verification,
    authorization, the scope switches) or change who may act (members, keys). An
    automated caller — a leaked integration key, an agent that read something it
    should not have followed — must be structurally unable to do those to itself.
    A person, in a session, does them; the audit log records who.
    """
    if not principal.is_human:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "this action requires an interactive session; API keys cannot perform it",
        )
    return principal


_MUTATING = frozenset({"POST", "PUT", "PATCH", "DELETE"})
