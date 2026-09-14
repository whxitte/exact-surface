"""The audit log, read side. Who did what, most recent first."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query

from api.deps import Principal, clean_doc, get_mongo_dep, get_principal
from db.audit_log import AuditLogRepo

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("")
async def list_events(
    limit: int = Query(100, ge=1, le=500),
    before: datetime | None = Query(None, description="Page backwards from this timestamp"),
    program_id: str | None = Query(None),
    actor: str | None = Query(None, description="A user id or API key id"),
    principal: Principal = Depends(get_principal),
    mongo: Any = Depends(get_mongo_dep),
) -> dict:
    """Recent audit events for the caller's tenant. Every mutating API call produces
    one, succeeded or refused, so this is also where a key's rejected attempts show."""
    rows = await AuditLogRepo.from_mongo(mongo).list(
        principal.tenant_id, limit=limit, before=before, program_id=program_id, actor_id=actor
    )
    return {"events": [clean_doc(r) for r in rows]}
