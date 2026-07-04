"""Cloud bucket enumeration (module 23) — S3/GCS/Azure permutation discovery.

Generates likely bucket names from a base (domain label / org) across common
suffixes and providers, then checks existence via an injected HTTP checker. A
non-404 means the bucket exists; 200 means it is publicly listable (the finding).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

Checker = Callable[[str], Awaitable[int | None]]  # returns HTTP status or None

_SUFFIXES = (
    "",
    "-backup",
    "-backups",
    "-dev",
    "-staging",
    "-prod",
    "-assets",
    "-static",
    "-media",
    "-uploads",
    "-data",
    "-logs",
    "-public",
    "-private",
    "-files",
)
_PROVIDERS = {
    "s3": "{name}.s3.amazonaws.com",
    "gcs": "{name}.storage.googleapis.com",
    "azure": "{name}.blob.core.windows.net",
}


def permutations(base: str) -> list[tuple[str, str, str]]:
    """Return ``(provider, bucket_name, url)`` candidates for *base*."""
    base = base.split(".")[0].lower()  # domain label only
    out: list[tuple[str, str, str]] = []
    for suffix in _SUFFIXES:
        name = f"{base}{suffix}"
        for provider, template in _PROVIDERS.items():
            out.append((provider, name, "https://" + template.format(name=name)))
    return out


async def enumerate_buckets(base: str, *, checker: Checker) -> list[dict]:
    """Return existing buckets: ``{provider, name, url, status, public}``."""
    results: list[dict] = []
    for provider, name, url in permutations(base):
        status = await checker(url)
        if status is not None and status != 404:
            results.append(
                {
                    "provider": provider,
                    "name": name,
                    "url": url,
                    "status": status,
                    "public": status == 200,
                }
            )
    return results
