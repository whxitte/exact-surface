"""Per-tenant notification channel CRUD."""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, status

from api.deps import Principal, clean_doc, get_mongo_dep, get_principal
from api.schemas import NotificationChannelCreate
from core.models import NotificationChannel
from db.notifications import NotificationChannelRepo

router = APIRouter(prefix="/notifications", tags=["notifications"])


@router.get("")
async def list_channels(
    principal: Principal = Depends(get_principal), mongo: Any = Depends(get_mongo_dep)
) -> list[dict]:
    docs = await NotificationChannelRepo.from_mongo(mongo).list(principal.tenant_id)
    return [clean_doc(d) for d in docs]


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_channel(
    body: NotificationChannelCreate,
    principal: Principal = Depends(get_principal),
    mongo: Any = Depends(get_mongo_dep),
) -> dict:
    channel = NotificationChannel(
        tenant_id=principal.tenant_id,
        channel_id="ch_" + uuid.uuid4().hex[:12],
        name=body.name,
        type=body.type,
        min_severity=body.min_severity,
        config=body.config,
    )
    await NotificationChannelRepo.from_mongo(mongo).save(channel)
    return clean_doc(channel.model_dump(mode="json"))


@router.delete("/{channel_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_channel(
    channel_id: str,
    principal: Principal = Depends(get_principal),
    mongo: Any = Depends(get_mongo_dep),
) -> None:
    await NotificationChannelRepo.from_mongo(mongo).delete(principal.tenant_id, channel_id)
