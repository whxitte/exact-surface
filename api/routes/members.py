"""Tenant member & permission-group management (§ RBAC / access control).

Every route here is **owner-only and non-delegable**: the router itself depends on
:func:`~api.deps.require_owner`, so only the tenant owner can create users, compose
permission groups, and assign membership. That is what makes privilege escalation
impossible by construction — there is no assignable permission that grants access to
this router, and the owner role can never be conferred through it (created users are
always ``MEMBER``). Every operation is scoped to the caller's tenant, so an id from
another tenant simply 404s.

Invariants enforced below:

* A created user starts with the groups the owner picked (validated to exist in the
  tenant) — or none, i.e. no access at all.
* The owner account is not manageable here: it can't be re-grouped, demoted, or
  deleted, so a tenant can never be left without an owner.
* Group permissions are normalised (unknown values dropped; a ``*.manage`` implies
  VIEW), so a group can only ever hold real, coherent permissions.
* The seeded default "Viewer" group can be re-permissioned or renamed but not deleted.
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, Field

from api.auth import hash_password
from api.deps import Principal, get_mongo_dep, get_principal, require_owner
from core.models import Group, Role, User
from core.permissions import PERMISSION_CATALOGUE, normalise_permissions
from db.groups import GroupRepo
from db.users import UserRepo

# Owner-only for the entire router (see module docstring).
router = APIRouter(prefix="/members", tags=["members"], dependencies=[Depends(require_owner)])


# -- request bodies ----------------------------------------------------------
class GroupCreate(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    permissions: list[str] = Field(default_factory=list)


class GroupUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=80)
    permissions: list[str] | None = None


class MemberCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=200)
    group_ids: list[str] = Field(default_factory=list)


class MemberGroups(BaseModel):
    group_ids: list[str] = Field(default_factory=list)


# -- projections -------------------------------------------------------------
def _public_user(doc: dict) -> dict:
    """Only the safe fields — never the password hash or verification token."""
    return {
        "user_id": doc["user_id"],
        "email": doc.get("email"),
        "role": doc.get("role", Role.MEMBER.value),
        "group_ids": doc.get("group_ids") or [],
        "email_verified": bool(doc.get("email_verified")),
    }


def _public_group(doc: dict) -> dict:
    return {
        "group_id": doc["group_id"],
        "name": doc.get("name"),
        "permissions": doc.get("permissions") or [],
        "is_default": bool(doc.get("is_default")),
    }


async def _validate_group_ids(mongo: Any, tenant_id: str, group_ids: list[str]) -> list[str]:
    """Reject any group id that isn't a real group in this tenant (deduped, order-kept).

    Rejecting rather than silently dropping means the owner can't accidentally
    assign a mistyped/foreign id and believe access was granted."""
    wanted = list(dict.fromkeys(group_ids))  # dedupe, preserve order
    if not wanted:
        return []
    rows = await GroupRepo.from_mongo(mongo).list_by_ids(tenant_id, wanted)
    found = {g["group_id"] for g in rows}
    missing = [gid for gid in wanted if gid not in found]
    if missing:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"unknown group(s): {', '.join(missing)}")
    return wanted


# -- permission catalogue ----------------------------------------------------
@router.get("/permissions")
async def list_permissions() -> list[dict]:
    """The grantable permissions, for the UI to render as checkboxes."""
    return [
        {"key": key, "label": label, "description": desc}
        for key, label, desc in PERMISSION_CATALOGUE
    ]


# -- groups ------------------------------------------------------------------
@router.get("/groups")
async def list_groups(
    principal: Principal = Depends(get_principal), mongo: Any = Depends(get_mongo_dep)
) -> list[dict]:
    groups = await GroupRepo.from_mongo(mongo).list(principal.tenant_id)
    return [_public_group(g) for g in groups]


@router.post("/groups", status_code=status.HTTP_201_CREATED)
async def create_group(
    body: GroupCreate,
    principal: Principal = Depends(get_principal),
    mongo: Any = Depends(get_mongo_dep),
) -> dict:
    group = Group(
        tenant_id=principal.tenant_id,
        group_id="g_" + uuid.uuid4().hex[:12],
        name=body.name.strip(),
        permissions=sorted(normalise_permissions(body.permissions)),
    )
    doc = await GroupRepo.from_mongo(mongo).save(group)
    return _public_group(doc)


@router.patch("/groups/{group_id}")
async def update_group(
    group_id: str,
    body: GroupUpdate,
    principal: Principal = Depends(get_principal),
    mongo: Any = Depends(get_mongo_dep),
) -> dict:
    repo = GroupRepo.from_mongo(mongo)
    existing = await repo.get(principal.tenant_id, group_id)
    if not existing:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "group not found")
    group = Group(
        tenant_id=principal.tenant_id,
        group_id=group_id,
        name=(body.name.strip() if body.name is not None else existing.get("name", "")),
        permissions=(
            sorted(normalise_permissions(body.permissions))
            if body.permissions is not None
            else (existing.get("permissions") or [])
        ),
        is_default=bool(existing.get("is_default")),
    )
    doc = await repo.save(group)
    return _public_group(doc)


@router.delete("/groups/{group_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_group(
    group_id: str,
    principal: Principal = Depends(get_principal),
    mongo: Any = Depends(get_mongo_dep),
) -> None:
    repo = GroupRepo.from_mongo(mongo)
    existing = await repo.get(principal.tenant_id, group_id)
    if not existing:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "group not found")
    if existing.get("is_default"):
        raise HTTPException(status.HTTP_409_CONFLICT, "the default Viewer group cannot be deleted")
    # Remove the group from every member who has it, so no dangling reference is left.
    users = UserRepo.from_mongo(mongo)
    for u in await users.list(principal.tenant_id):
        gids = u.get("group_ids") or []
        if group_id in gids:
            await users.set_groups(
                principal.tenant_id, u["user_id"], [g for g in gids if g != group_id]
            )
    await repo.delete(principal.tenant_id, group_id)


# -- members -----------------------------------------------------------------
@router.get("")
async def list_members(
    principal: Principal = Depends(get_principal), mongo: Any = Depends(get_mongo_dep)
) -> list[dict]:
    users = await UserRepo.from_mongo(mongo).list(principal.tenant_id)
    return [_public_user(u) for u in users]


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_member(
    body: MemberCreate,
    principal: Principal = Depends(get_principal),
    mongo: Any = Depends(get_mongo_dep),
) -> dict:
    users = UserRepo.from_mongo(mongo)
    if await users.get_by_email(body.email):
        raise HTTPException(status.HTTP_409_CONFLICT, "email already registered")
    group_ids = await _validate_group_ids(mongo, principal.tenant_id, body.group_ids)
    # Always MEMBER — the owner role is never conferred through this API.
    user = User(
        tenant_id=principal.tenant_id,
        user_id="u_" + uuid.uuid4().hex[:12],
        email=body.email,
        password_hash=hash_password(body.password),
        role=Role.MEMBER,
        group_ids=group_ids,
        # An owner-provisioned account is trusted; skip the email round-trip.
        email_verified=True,
    )
    doc = await users.create(user)
    return _public_user(doc)


@router.patch("/{user_id}")
async def set_member_groups(
    user_id: str,
    body: MemberGroups,
    principal: Principal = Depends(get_principal),
    mongo: Any = Depends(get_mongo_dep),
) -> dict:
    users = UserRepo.from_mongo(mongo)
    target = await users.get(principal.tenant_id, user_id)
    if not target:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    if target.get("role") == Role.OWNER.value:
        # The owner has every permission implicitly; groups don't apply and must not be
        # used to imply a demotion.
        raise HTTPException(status.HTTP_409_CONFLICT, "the owner account cannot be modified")
    group_ids = await _validate_group_ids(mongo, principal.tenant_id, body.group_ids)
    await users.set_groups(principal.tenant_id, user_id, group_ids)
    return _public_user({**target, "group_ids": group_ids})


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_member(
    user_id: str,
    principal: Principal = Depends(get_principal),
    mongo: Any = Depends(get_mongo_dep),
) -> None:
    users = UserRepo.from_mongo(mongo)
    target = await users.get(principal.tenant_id, user_id)
    if not target:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    if target.get("role") == Role.OWNER.value:
        # Never leave a tenant ownerless (and an owner can't delete themselves here).
        raise HTTPException(status.HTTP_409_CONFLICT, "the owner account cannot be deleted")
    await users.delete(principal.tenant_id, user_id)
