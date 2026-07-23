"""License-gated update client (§ commercial — freshness enforcement).

The instance periodically pulls the latest **signed** template/tool bundle from the
vendor control plane's update feed, presenting its license. The feed refuses a lapsed
subscription (402), so a non-subscriber's detections rot — the durable enforcement for a
security product. Everything the instance applies is verified against the embedded public
key and a content hash, so a hostile mirror or a corrupted download can never inject
templates the vendor didn't sign.

The security-critical steps — verify the manifest signature, verify the bundle hash — are
pure and unit-tested. Network + extraction live in :func:`run_update`, which takes
injected fetchers so it is offline-testable too.
"""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from core.license import verify_blob
from core.logging import logger


def verify_manifest(response: dict, public_key_pem: str) -> dict | None:
    """Return the manifest dict iff its detached signature verifies, else None. The
    manifest bytes are canonicalised exactly as the server signed them (sorted, compact)."""
    manifest = (response or {}).get("manifest")
    signature = (response or {}).get("signature")
    if not isinstance(manifest, dict) or not isinstance(signature, str):
        return None
    blob = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    return manifest if verify_blob(blob, signature, public_key_pem) else None


def is_newer(manifest: dict, current_version: str | None) -> bool:
    version = str(manifest.get("version") or "")
    return bool(version) and version != (current_version or "")


def apply_bundle(bundle: bytes, expected_sha256: str | None, dest_dir: str | Path) -> None:
    """Verify the bundle hash, then extract it into *dest_dir*. Refuses on hash mismatch —
    a tampered/corrupt bundle is never written."""
    if expected_sha256:
        actual = hashlib.sha256(bundle).hexdigest()
        if actual != expected_sha256:
            raise ValueError(f"bundle hash mismatch: {actual} != {expected_sha256}")
    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(bundle), mode="r:*") as tar:
        _safe_extract(tar, dest)


def _safe_extract(tar: tarfile.TarFile, dest: Path) -> None:
    """Extract, refusing any member that would escape *dest* (path traversal / absolute)."""
    dest = dest.resolve()
    for member in tar.getmembers():
        target = (dest / member.name).resolve()
        if not str(target).startswith(str(dest)):
            raise ValueError(f"refusing unsafe path in bundle: {member.name}")
    tar.extractall(dest)  # noqa: S202 - members validated above


JsonGet = Callable[[str, dict], Awaitable[dict]]
BytesGet = Callable[[str], Awaitable[bytes]]


async def run_update(
    *,
    mongo: Any,
    feed_url: str,
    license_token: str | None,
    public_key_pem: str,
    dest_dir: str,
    json_get: JsonGet,
    bytes_get: BytesGet,
) -> dict:
    """Fetch → verify → (if newer) download → verify hash → extract → record version."""
    from db.license_state import LicenseStateRepo

    repo = LicenseStateRepo.from_mongo(mongo)
    url = f"{feed_url.rstrip('/')}/v1/updates/manifest"
    resp = await json_get(url, {"X-License": license_token or ""})
    manifest = verify_manifest(resp, public_key_pem)
    if manifest is None:
        logger.warning("update feed: manifest signature invalid — ignoring")
        return {"applied": False, "reason": "invalid signature"}

    current = await repo.applied_update_version()
    if not is_newer(manifest, current):
        return {"applied": False, "reason": "already current", "version": current}

    url = manifest.get("templates_url")
    if not url:
        return {"applied": False, "reason": "no bundle url"}
    bundle = await bytes_get(url)
    apply_bundle(bundle, manifest.get("sha256"), dest_dir)
    await repo.set_applied_update_version(str(manifest["version"]))
    logger.info("update feed: applied bundle {}", manifest["version"])
    return {"applied": True, "version": manifest["version"]}


async def _default_json_get(url: str, headers: dict) -> dict:  # pragma: no cover - network
    import aiohttp

    async with aiohttp.ClientSession() as s:
        async with s.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=20)) as r:
            if r.status != 200:
                return {}
            return await r.json()


async def _default_bytes_get(url: str) -> bytes:  # pragma: no cover - network
    import aiohttp

    async with aiohttp.ClientSession() as s:
        async with s.get(url, timeout=aiohttp.ClientTimeout(total=120)) as r:
            r.raise_for_status()
            return await r.content.read(200_000_000)  # cap at 200 MB


async def check_for_updates(mongo: Any) -> dict:
    """Best-effort update poll using the configured feed. No-op when unconfigured; never
    raises (a failed update must never take an instance down)."""
    from core.config import get_settings

    settings = get_settings()
    if not settings.update_feed_url or not settings.license_public_key:
        return {"applied": False, "reason": "updates not configured"}
    from core.entitlements import current

    try:
        token = None
        ent = current().entitlements
        # reuse whatever token the instance is running on (env/file/stored)
        from db.license_state import LicenseStateRepo

        token = await LicenseStateRepo.from_mongo(mongo).stored_token() or settings.license_token
        _ = ent  # entitlements presence is informational; the feed re-checks the token
        return await run_update(
            mongo=mongo,
            feed_url=settings.update_feed_url,
            license_token=token,
            public_key_pem=settings.license_public_key,
            dest_dir=settings.update_templates_dir,
            json_get=_default_json_get,
            bytes_get=_default_bytes_get,
        )
    except Exception as exc:  # noqa: BLE001 - updates are best-effort
        logger.warning("update check failed: {}", exc)
        return {"applied": False, "reason": str(exc)}
