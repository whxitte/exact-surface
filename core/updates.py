"""Update client for fetching template and tool bundles."""

from __future__ import annotations

import hashlib
import io
import json
import os
import tarfile
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from core.logging import logger
from core.signing import verify_blob


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
    """Extract, refusing any member that would escape *dest*.

    Two layers. The explicit check names the offending member in the error, which is
    what an operator needs to see. The stdlib ``data`` filter underneath also refuses
    what a name check cannot: a symlink or hardlink whose *target* escapes, device
    nodes, and setuid/setgid bits. The bundle is signature-verified before it gets
    here, so this only matters if the signing key is compromised — which is precisely
    when it matters most.
    """
    dest = dest.resolve()
    for member in tar.getmembers():
        target = (dest / member.name).resolve()
        if not str(target).startswith(str(dest) + os.sep) and target != dest:
            raise ValueError(f"refusing unsafe path in bundle: {member.name}")
    tar.extractall(dest, filter="data")


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
    url = f"{feed_url.rstrip('/')}/v1/updates/manifest"
    resp = await json_get(url, {})
    manifest = verify_manifest(resp, public_key_pem)
    if manifest is None:
        logger.warning("update feed: manifest signature invalid — ignoring")
        return {"applied": False, "reason": "invalid signature"}

    col = mongo.collection("update_state")
    state = await col.find_one({"_id": "update"}) if hasattr(mongo, "collection") else None
    current = (state or {}).get("version") if state else None

    if not is_newer(manifest, current):
        return {"applied": False, "reason": "already current", "version": current}

    url = manifest.get("templates_url")
    if not url:
        return {"applied": False, "reason": "no bundle url"}
    bundle = await bytes_get(url)
    apply_bundle(bundle, manifest.get("sha256"), dest_dir)
    if hasattr(mongo, "collection"):
        await col.update_one(
            {"_id": "update"},
            {"$set": {"version": str(manifest["version"])}},
            upsert=True,
        )
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
    """Best-effort update poll using the configured feed. No-op when unconfigured."""
    from core.config import get_settings

    settings = get_settings()
    if not settings.update_feed_url:
        return {"applied": False, "reason": "updates not configured"}

    try:
        return await run_update(
            mongo=mongo,
            feed_url=settings.update_feed_url,
            license_token=None,
            public_key_pem=settings.update_public_key or "",
            dest_dir=settings.update_templates_dir,
            json_get=_default_json_get,
            bytes_get=_default_bytes_get,
        )
    except Exception as exc:  # noqa: BLE001 - updates are best-effort
        logger.warning("update check failed: {}", exc)
        return {"applied": False, "reason": str(exc)}
