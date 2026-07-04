"""CVE-to-asset match collection access."""

from __future__ import annotations

from db.base import Repository


class CveMatchRepo(Repository):
    COLLECTION = "cve_matches"
