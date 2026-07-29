"""Mined JavaScript bundles (module: js_mine)."""

from __future__ import annotations

from db.base import Repository


class JsFileRepo(Repository):
    COLLECTION = "js_files"
