"""Per-tenant integration secrets (API keys) — list / set / clear.

Values are write-only over the API: a set is accepted, but reads only ever return
the masked preview and a ``configured`` flag, never the plaintext.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from api.deps import Principal, get_mongo_dep, get_principal
from core.integrations import INTEGRATION_BY_NAME, INTEGRATION_KEYS
from db.integrations import IntegrationSecretRepo

router = APIRouter(prefix="/integrations", tags=["integrations"])


class IntegrationSet(BaseModel):
    value: str = Field(min_length=1, max_length=4096)


@router.get("")
async def list_integrations(
    principal: Principal = Depends(get_principal), mongo: Any = Depends(get_mongo_dep)
) -> list[dict]:
    """Every known integration with whether the tenant has configured it (and a
    masked preview). Order matches the registry so the UI is stable."""
    stored = {
        d["name"]: d
        for d in await IntegrationSecretRepo.from_mongo(mongo).list(principal.tenant_id)
    }
    out = []
    for k in INTEGRATION_KEYS:
        doc = stored.get(k.name)
        out.append(
            {
                "name": k.name,
                "label": k.label,
                "help": k.help,
                "secret": k.secret,
                "configured": bool(doc),
                "masked": (doc or {}).get("masked", ""),
            }
        )
    return out


@router.put("/{name}", status_code=status.HTTP_204_NO_CONTENT)
async def set_integration(
    name: str,
    body: IntegrationSet,
    principal: Principal = Depends(get_principal),
    mongo: Any = Depends(get_mongo_dep),
) -> None:
    # Write access is enforced at the router (SETTINGS_MANAGE); owner always qualifies.
    if name not in INTEGRATION_BY_NAME:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"unknown integration '{name}'")
    await IntegrationSecretRepo.from_mongo(mongo).set(principal.tenant_id, name, body.value.strip())


@router.delete("/{name}", status_code=status.HTTP_204_NO_CONTENT)
async def clear_integration(
    name: str,
    principal: Principal = Depends(get_principal),
    mongo: Any = Depends(get_mongo_dep),
) -> None:
    if name not in INTEGRATION_BY_NAME:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"unknown integration '{name}'")
    await IntegrationSecretRepo.from_mongo(mongo).delete(principal.tenant_id, name)
