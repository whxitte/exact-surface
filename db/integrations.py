"""Per-tenant integration secrets (API keys), encrypted at rest.

The stored document keeps the ciphertext (``value_enc``) plus a non-reversible
``masked`` preview for display — the plaintext is only ever produced by
:meth:`get_value` / :func:`resolve_secret` at the point a tool needs it.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from core.crypto import decrypt, encrypt
from core.integrations import INTEGRATION_BY_NAME
from core.secrets_policy import mask


class IntegrationSecretRepo:
    def __init__(self, collection: Any) -> None:
        self._c = collection

    @classmethod
    def from_mongo(cls, mongo: Any) -> IntegrationSecretRepo:
        return cls(mongo.collection("integration_secrets"))

    async def set(self, tenant_id: str, name: str, value: str) -> dict:
        doc = {
            "tenant_id": tenant_id,
            "name": name,
            "value_enc": encrypt(value),
            "masked": mask(value),
            "updated_at": datetime.now(UTC),
        }
        await self._c.update_one({"tenant_id": tenant_id, "name": name}, {"$set": doc}, upsert=True)
        return doc

    async def get_value(self, tenant_id: str, name: str) -> str | None:
        doc = await self._c.find_one({"tenant_id": tenant_id, "name": name})
        if not doc or not doc.get("value_enc"):
            return None
        return decrypt(doc["value_enc"])

    async def list(self, tenant_id: str) -> list[dict]:
        return await self._c.find({"tenant_id": tenant_id}).limit(100).to_list(100)

    async def delete(self, tenant_id: str, name: str) -> None:
        await self._c.delete_one({"tenant_id": tenant_id, "name": name})


async def resolve_secret(mongo: Any, tenant_id: str, name: str) -> str | None:
    """Resolve an integration value: the tenant's stored key wins, then the
    process-wide ``.env`` fallback from :class:`Settings`. ``None`` if neither is
    set, which callers treat as "integration not configured → skip"."""
    val = await IntegrationSecretRepo.from_mongo(mongo).get_value(tenant_id, name)
    if val:
        return val

    key = INTEGRATION_BY_NAME.get(name)
    if not key or not key.settings_attr:
        return None
    from pydantic import SecretStr

    from core.config import get_settings

    raw = getattr(get_settings(), key.settings_attr, None)
    if raw is None:
        return None
    return raw.get_secret_value() if isinstance(raw, SecretStr) else str(raw)
