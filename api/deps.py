"""Shared API dependencies: principal resolution + tenant-ownership guards (§3.7).

Tenant isolation is enforced *here*, centrally: every data route depends on
``require_program`` (or filters by ``principal.tenant_id``), so a valid token for
tenant A can never reach tenant B's data even by guessing a program id — the
lookup is scoped to the caller's tenant and returns 404 for anything else.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from fastapi import Depends, Header, HTTPException, status

from api.auth import InvalidToken, decode_token, hash_api_key
from core.models import Role
from core.verification import DomainVerifier
from db.apikeys import ApiKeyRepo
from db.mongo import get_mongo
from db.programs import ProgramRepo

_domain_verifier = DomainVerifier()


async def get_domain_verifier() -> DomainVerifier:
    """The domain verifier. Overridden in tests to avoid real DNS/HTTP."""
    return _domain_verifier


@dataclass(frozen=True)
class Principal:
    tenant_id: str
    user_id: str | None
    role: Role
    method: str  # "jwt" | "apikey"


async def get_mongo_dep() -> Any:
    """The Mongo handle. Overridden in tests via ``app.dependency_overrides``."""
    return get_mongo()


def clean_doc(doc: dict | None) -> dict | None:
    """Drop Mongo's ``_id`` so documents are JSON-serialisable in responses."""
    if doc is None:
        return None
    return {k: v for k, v in doc.items() if k != "_id"}


async def get_principal(
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None),
    mongo: Any = Depends(get_mongo_dep),
) -> Principal:
    if authorization and authorization.startswith("Bearer "):
        try:
            payload = decode_token(authorization[7:])
        except InvalidToken as exc:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid token") from exc
        return Principal(
            tenant_id=payload["tenant_id"],
            user_id=payload.get("sub"),
            role=Role(payload.get("role", "member")),
            method="jwt",
        )

    if x_api_key:
        doc = await ApiKeyRepo.from_mongo(mongo).get_by_hash(hash_api_key(x_api_key))
        if not doc:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid api key")
        return Principal(
            tenant_id=doc["tenant_id"],
            user_id=doc.get("created_by"),
            role=Role(doc.get("role", "member")),
            method="apikey",
        )

    raise HTTPException(
        status.HTTP_401_UNAUTHORIZED,
        "missing credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )


def require_role(*allowed: Role):
    async def _dep(principal: Principal = Depends(get_principal)) -> Principal:
        if principal.role not in allowed:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "insufficient role")
        return principal

    return _dep


# Privileged operations — account-level or security-critical (mint credentials,
# destroy a program, create the legal scanning-authorization record, manage
# integration secrets). Owners and admins only; members are read/operate.
require_owner = require_role(Role.OWNER, Role.ADMIN)


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
