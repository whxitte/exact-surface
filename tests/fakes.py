"""In-memory fakes implementing just enough of the motor collection API to test
the repository layer without a running MongoDB. Honors $setOnInsert/$set/upsert
and $in filters — the semantics the repository relies on."""

from __future__ import annotations

import itertools
from typing import Any


class _UpdateResult:
    def __init__(self, upserted_id: Any = None, modified: int = 0) -> None:
        self.upserted_id = upserted_id
        self.modified_count = modified


class _Cursor:
    def __init__(self, items: list[dict]) -> None:
        self._items = items

    def sort(self, *_a: Any, **_k: Any) -> _Cursor:
        return self

    def limit(self, n: int) -> _Cursor:
        self._items = self._items[:n]
        return self

    async def to_list(self, length: int | None = None) -> list[dict]:
        return self._items if length is None else self._items[:length]


def _matches(doc: dict, flt: dict) -> bool:
    for key, cond in flt.items():
        if isinstance(cond, dict) and "$in" in cond:
            if doc.get(key) not in cond["$in"]:
                return False
        elif doc.get(key) != cond:
            return False
    return True


class FakeCollection:
    def __init__(self) -> None:
        self.docs: dict[tuple, dict] = {}
        self._counter = itertools.count()

    def _key(self, doc: dict) -> tuple:
        ident = (
            doc.get("fingerprint")
            or doc.get("program_id")
            or doc.get("scan_id")
            or f"_auto{next(self._counter)}"
        )
        return (doc.get("tenant_id"), ident)

    async def update_one(self, flt: dict, update: dict, upsert: bool = False) -> _UpdateResult:
        found = next((d for d in self.docs.values() if _matches(d, flt)), None)
        if found is None:
            if not upsert:
                return _UpdateResult()
            doc: dict = {}
            doc.update(flt)
            doc.update(update.get("$setOnInsert", {}))
            doc.update(update.get("$set", {}))
            key = self._key(doc)
            self.docs[key] = doc
            return _UpdateResult(upserted_id=key)
        found.update(update.get("$set", {}))  # $setOnInsert ignored on existing
        return _UpdateResult(modified=1)

    async def insert_one(self, doc: dict) -> _UpdateResult:
        key = (doc.get("tenant_id"), f"_ins{next(self._counter)}")
        self.docs[key] = dict(doc)
        return _UpdateResult(upserted_id=key)

    async def update_many(self, flt: dict, update: dict) -> _UpdateResult:
        n = 0
        for d in self.docs.values():
            if _matches(d, flt):
                d.update(update.get("$set", {}))
                n += 1
        return _UpdateResult(modified=n)

    async def find_one(self, flt: dict) -> dict | None:
        d = next((d for d in self.docs.values() if _matches(d, flt)), None)
        return dict(d) if d else None

    def find(self, flt: dict | None = None) -> _Cursor:
        return _Cursor([dict(d) for d in self.docs.values() if _matches(d, flt or {})])

    async def count_documents(self, flt: dict) -> int:
        return sum(1 for d in self.docs.values() if _matches(d, flt))


class FakeMongo:
    def __init__(self) -> None:
        self._collections: dict[str, FakeCollection] = {}

    def collection(self, name: str) -> FakeCollection:
        return self._collections.setdefault(name, FakeCollection())
