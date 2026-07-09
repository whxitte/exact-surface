"""Idempotent, tenant-scoped repository base (§3.1, §3.2).

Every stateful write is an upsert keyed on ``(tenant_id, fingerprint)``:
``$setOnInsert`` for immutable identity + ``first_seen`` + ``is_new=True``, and
``$set`` for volatile fields + ``last_seen``. Consequences:

* Re-running any module N times leaves the DB identical to running it once.
* ``is_new`` becomes True exactly once, on the genuine insert, and is left alone
  on subsequent observations — the delta/alert consumer clears it via
  :meth:`Repository.clear_is_new`, so an alert fires once per real appearance.

The repository is written against the motor collection API but takes the
collection by injection, so it is fully testable against an in-memory fake
(``tests/fakes.py``) without a running MongoDB.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel

#: Fields set only on insert; never overwritten by a later observation.
IMMUTABLE_FIELDS: frozenset[str] = frozenset(
    {"tenant_id", "program_id", "fingerprint", "first_seen", "created_at", "is_new"}
)


@dataclass
class UpsertResult:
    fingerprint: str
    inserted: bool  # True == genuinely new (is_new fired this call)


def _to_bson(value: Any) -> Any:
    """Recursively convert Enums to their values; leave datetimes/primitives intact."""
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {k: _to_bson(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_to_bson(v) for v in value]
    return value


class Repository:
    COLLECTION: str = ""
    #: Fields the user controls, not the scanner: written once on insert, then never
    #: overwritten by a later observation (so a manual toggle survives every re-scan).
    #: Flip them explicitly via :meth:`set_flag`.
    PRESERVE_FIELDS: frozenset[str] = frozenset()

    def __init__(self, collection: Any) -> None:
        self._c = collection

    @classmethod
    def from_mongo(cls, mongo: Any) -> Repository:
        return cls(mongo.collection(cls.COLLECTION))

    async def upsert(self, model: BaseModel) -> UpsertResult:
        doc = _to_bson(model.model_dump(mode="python"))
        now = datetime.now(UTC)

        set_on_insert: dict[str, Any] = {}
        set_fields: dict[str, Any] = {}
        preserve = IMMUTABLE_FIELDS | self.PRESERVE_FIELDS
        for key, val in doc.items():
            (set_on_insert if key in preserve else set_fields)[key] = val

        set_on_insert.setdefault("first_seen", now)
        set_on_insert.setdefault("created_at", now)
        set_on_insert["is_new"] = True  # only applied on insert
        set_fields["last_seen"] = now
        set_fields["updated_at"] = now

        flt = {"tenant_id": doc["tenant_id"], "fingerprint": doc["fingerprint"]}
        res = await self._c.update_one(
            flt, {"$setOnInsert": set_on_insert, "$set": set_fields}, upsert=True
        )
        return UpsertResult(doc["fingerprint"], res.upserted_id is not None)

    async def upsert_all(self, models: list[BaseModel]) -> list[UpsertResult]:
        """Upsert each model, returning per-item results (so callers know which are new)."""
        return [await self.upsert(model) for model in models]

    async def upsert_many(self, models: list[BaseModel]) -> tuple[int, int]:
        """Return (total, newly_inserted)."""
        results = await self.upsert_all(models)
        return len(results), sum(1 for r in results if r.inserted)

    async def get(self, tenant_id: str, fingerprint: str) -> dict | None:
        return await self._c.find_one({"tenant_id": tenant_id, "fingerprint": fingerprint})

    async def list(
        self,
        tenant_id: str,
        program_id: str | None = None,
        is_new: bool | None = None,
        limit: int = 100,
    ) -> list[dict]:
        flt: dict[str, Any] = {"tenant_id": tenant_id}
        if program_id is not None:
            flt["program_id"] = program_id
        if is_new is not None:
            flt["is_new"] = is_new
        return await self._c.find(flt).limit(limit).to_list(limit)

    async def count(self, tenant_id: str, program_id: str | None = None) -> int:
        flt: dict[str, Any] = {"tenant_id": tenant_id}
        if program_id is not None:
            flt["program_id"] = program_id
        return await self._c.count_documents(flt)

    async def set_flag(self, tenant_id: str, fingerprint: str, field: str, value: Any) -> bool:
        """Set a single user-controlled field on one record. Returns True if it
        matched a document. Used for :attr:`PRESERVE_FIELDS` toggles."""
        res = await self._c.update_one(
            {"tenant_id": tenant_id, "fingerprint": fingerprint},
            {"$set": {field: value, "updated_at": datetime.now(UTC)}},
        )
        return bool(getattr(res, "modified", 0) or getattr(res, "modified_count", 0))

    async def clear_is_new(self, tenant_id: str, fingerprints: list[str]) -> None:
        """Consumer marks records as seen so they never re-alert as 'new'."""
        await self._c.update_many(
            {"tenant_id": tenant_id, "fingerprint": {"$in": fingerprints}},
            {"$set": {"is_new": False}},
        )
