"""Build identity — baked at image build time, not configurable at runtime."""

from __future__ import annotations

#: Semantic version of the build ("1.4.0"), or "dev" for a source checkout.
VERSION: str = "dev"

#: Git commit the image was built from.
COMMIT: str = "unknown"

#: Build timestamp, ISO-8601.
BUILT_AT: str = ""

def summary() -> dict:
    """What /health and the footer report."""
    return {
        "version": VERSION,
        "commit": COMMIT,
        "built_at": BUILT_AT,
    }
