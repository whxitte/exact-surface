"""Subscription store for the control plane — who has paid through when.

Deliberately a simple JSON file so the vendor can start without a database (swap for
Postgres later behind the same interface). One record per license: the real
subscription end (`paid_until`) and a status the vendor flips on payment / non-payment /
cancellation. The refresh endpoint mints short rolling tokens up to `paid_until`; letting
it lapse (or suspending) is how you turn a customer read-only.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path


@dataclass
class LicenseRecord:
    license_id: str
    customer_id: str
    customer_name: str
    plan: str
    max_domains: int | None
    paid_until: str  # ISO-8601 — subscription is valid through this instant
    status: str = "active"  # "active" | "suspended"
    grace_days: int = 14

    def paid_until_dt(self) -> datetime:
        dt = datetime.fromisoformat(self.paid_until)
        return dt if dt.tzinfo else dt.replace(tzinfo=UTC)

    def is_current(self, now: datetime) -> bool:
        return self.status == "active" and now < self.paid_until_dt()


class LicenseStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def _load(self) -> dict[str, dict]:
        if not self.path.exists():
            return {}
        return json.loads(self.path.read_text() or "{}")

    def get(self, license_id: str) -> LicenseRecord | None:
        raw = self._load().get(license_id)
        return LicenseRecord(**raw) if raw else None

    def upsert(self, record: LicenseRecord) -> None:
        data = self._load()
        data[record.license_id] = asdict(record)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(data, indent=2, sort_keys=True))

    def suspend(self, license_id: str) -> bool:
        data = self._load()
        if license_id not in data:
            return False
        data[license_id]["status"] = "suspended"
        self.path.write_text(json.dumps(data, indent=2, sort_keys=True))
        return True

    def all(self) -> list[LicenseRecord]:
        return [LicenseRecord(**r) for r in self._load().values()]
