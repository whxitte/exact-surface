"""Open-port collection access."""

from __future__ import annotations

from db.base import Repository


class PortRepo(Repository):
    COLLECTION = "ports"
