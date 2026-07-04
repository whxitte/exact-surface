"""HTTP endpoint collection access."""

from __future__ import annotations

from db.base import Repository


class EndpointRepo(Repository):
    COLLECTION = "endpoints"
