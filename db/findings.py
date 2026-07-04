"""Finding collection access (nuclei / secret / port / dork findings)."""

from __future__ import annotations

from db.base import Repository


class FindingRepo(Repository):
    COLLECTION = "findings"
