"""GitHub/OSINT leak collection access. Masked value + keyed hash only (§9c)."""

from __future__ import annotations

from db.base import Repository


class LeakRepo(Repository):
    COLLECTION = "leaks"
