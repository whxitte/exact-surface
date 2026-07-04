"""Asset collection access + is_new bookkeeping."""

from __future__ import annotations

from db.base import Repository


class AssetRepo(Repository):
    COLLECTION = "assets"
