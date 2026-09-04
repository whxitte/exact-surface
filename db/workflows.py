"""Saved Playground workflows — a user's canvas, per tenant."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any


class WorkflowRepo:
    """Canvases are opaque documents: nodes, edges and positions as the UI drew them.

    Deliberately not modelled field-by-field. The graph's *meaning* is validated by
    :func:`core.playground.validate` on save and again on every run — storing it as a
    schema here would be a third place to keep in sync with the node catalogue, and
    the run path must revalidate anyway (a document can be edited between save and run).
    """

    def __init__(self, collection: Any) -> None:
        self._c = collection

    @classmethod
    def from_mongo(cls, mongo: Any) -> WorkflowRepo:
        return cls(mongo.collection("workflows"))

    async def list(self, tenant_id: str, limit: int = 100) -> list[dict]:
        cursor = self._c.find({"tenant_id": tenant_id}).sort("updated_at", -1).limit(limit)
        return await cursor.to_list(limit)

    async def get(self, tenant_id: str, workflow_id: str) -> dict | None:
        return await self._c.find_one({"tenant_id": tenant_id, "workflow_id": workflow_id})

    async def save(
        self,
        *,
        tenant_id: str,
        workflow_id: str,
        name: str,
        graph: dict,
        program_id: str = "",
    ) -> dict:
        now = datetime.now(UTC)
        doc = {
            "tenant_id": tenant_id,
            "workflow_id": workflow_id,
            "name": name,
            "graph": graph,
            "program_id": program_id,
            "updated_at": now,
        }
        await self._c.update_one(
            {"tenant_id": tenant_id, "workflow_id": workflow_id},
            {"$set": doc, "$setOnInsert": {"created_at": now}},
            upsert=True,
        )
        return doc

    async def delete(self, tenant_id: str, workflow_id: str) -> None:
        await self._c.delete_one({"tenant_id": tenant_id, "workflow_id": workflow_id})
