"""Delta detection — what changed about an asset/endpoint since last time (module 23).

State-awareness (§3.1) is ExactSurface's defining behaviour, and deltas are how it shows
up to the user: a 403 becoming 200, a title/tech change, a new port, a cert change.
This module is a pure comparator — given the stored document and the fresh
observation, it returns the ``Delta`` events that occurred. Persisting and alerting
are the caller's job.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from core.hashing import asset_fingerprint
from core.models import Delta, DeltaKind, Endpoint


def compute_endpoint_deltas(
    tenant_id: str, program_id: str, old: dict | None, new: Endpoint
) -> list[Delta]:
    """Return the changes between a stored endpoint *old* and a fresh *new* one.

    A brand-new endpoint yields no deltas here — its novelty is captured by the
    asset/endpoint ``is_new`` flag, not a change event.
    """
    if old is None:
        return []

    host = urlsplit(new.url).hostname or ""
    asset_fp = asset_fingerprint(program_id, host)
    deltas: list[Delta] = []

    def _delta(kind: DeltaKind, before, after) -> Delta:
        return Delta(
            tenant_id=tenant_id,
            program_id=program_id,
            asset_fingerprint=asset_fp,
            kind=kind,
            before=str(before),
            after=str(after),
        )

    if old.get("status_code") != new.status_code:
        deltas.append(_delta(DeltaKind.STATUS_CHANGE, old.get("status_code"), new.status_code))

    if old.get("content_hash") != new.content_hash:
        deltas.append(_delta(DeltaKind.TITLE_CHANGE, old.get("title"), new.title))

    if set(old.get("tech") or []) != set(new.tech or []):
        deltas.append(
            _delta(DeltaKind.TECH_CHANGE, ",".join(old.get("tech") or []), ",".join(new.tech or []))
        )

    return deltas
