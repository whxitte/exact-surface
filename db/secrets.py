"""Exposed-secret collection access. Stores masked value + keyed hash only (§9c)."""

from __future__ import annotations

from db.base import Repository


class SecretRepo(Repository):
    COLLECTION = "secrets"
