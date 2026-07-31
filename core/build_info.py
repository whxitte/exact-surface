"""Build identity — baked at image build time, not configurable at runtime.

The problem this solves
-----------------------
Licence enforcement used to hang off ``EXACTSURFACE_LICENSE_ENFORCED``, an ordinary
setting. On a self-hosted product that is not a control at all: the customer runs the
container, so ``docker run -e EXACTSURFACE_LICENSE_ENFORCED=false`` turned the entire
subscription off. Every signature check, expiry check and quota downstream of it became
decorative.

So the release build states its own identity. ``scripts/stamp_build.py`` rewrites this
file during ``docker build`` with ``RELEASE_BUILD = True``; a source checkout keeps the
``False`` below. :func:`licence_enforced` then reads:

    enforced = RELEASE_BUILD or settings.license_enforced

A release image is therefore enforced *because of what it is*, and no environment
variable can say otherwise.

What this does and does not achieve
-----------------------------------
It moves the bypass from **"set an env var"** — which any customer can do, by accident
even — to **"edit the source and rebuild the image"**, which is a deliberate act by
someone with the source, and is the boundary ``core/license.py`` already documents as
un-defendable in self-hosted software. That is the honest claim: this is not
unbreakable, it is *not trivially breakable*, which is a completely different property.

The real backstops remain the licence contract, the per-customer watermark below, and
the update stream — a security scanner with three-month-old templates is worthless, and
updates come from the vendor's server.
"""

from __future__ import annotations

#: True only in an image produced by the release pipeline. Rewritten by
#: scripts/stamp_build.py at build time — do not edit by hand.
RELEASE_BUILD: bool = False

#: Semantic version of the build ("1.4.0"), or "dev" for a source checkout.
VERSION: str = "dev"

#: Git commit the image was built from — what a support conversation starts with.
COMMIT: str = "unknown"

#: Build timestamp, ISO-8601.
BUILT_AT: str = ""

#: The customer this image was built for. A per-customer watermark: if an image leaks,
#: this says whose it was. Empty on a generic/dev build.
LICENSED_TO: str = ""


def is_release() -> bool:
    return bool(RELEASE_BUILD)


def licence_enforced(settings_flag: bool) -> bool:
    """Whether licence enforcement is active.

    A release build is always enforced. A source checkout honours the setting, so
    developers can run unlicensed and tests can exercise both paths.
    """
    return True if RELEASE_BUILD else bool(settings_flag)


def summary() -> dict:
    """What ``/health`` and the footer report. Never includes anything secret — the
    licence *public* key and the customer name are both fine to show; the token is not
    and is deliberately absent."""
    return {
        "version": VERSION,
        "commit": COMMIT,
        "built_at": BUILT_AT,
        "release": RELEASE_BUILD,
        "licensed_to": LICENSED_TO or None,
    }
