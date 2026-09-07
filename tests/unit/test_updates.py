"""The license-gated update client (core.updates) — verify + apply.

The security-critical properties are pinned here: the instance applies a bundle only if
the manifest is signed by the vendor's key and the bundle's hash matches, and a bundle
can never write outside its destination (path-traversal guard).
"""

from __future__ import annotations

import hashlib
import io
import json
import tarfile

import pytest

from core.signing import generate_keypair, sign_blob
from core.updates import apply_bundle, is_newer, run_update, verify_manifest
from tests.fakes import FakeMongo


def _signed(manifest: dict, priv: str) -> dict:
    blob = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    return {"manifest": manifest, "signature": sign_blob(blob, priv)}


def _tar_bytes(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


# -- manifest verification ---------------------------------------------------
def test_signed_manifest_verifies():
    priv, pub = generate_keypair()
    m = {"version": "1", "sha256": "x", "templates_url": "https://u/x"}
    assert verify_manifest(_signed(m, priv), pub) == m


def test_tampered_manifest_rejected():
    priv, pub = generate_keypair()
    signed = _signed({"version": "1"}, priv)
    signed["manifest"]["version"] = "2"  # change after signing
    assert verify_manifest(signed, pub) is None


def test_wrong_key_manifest_rejected():
    priv, _pub = generate_keypair()
    _priv2, pub2 = generate_keypair()
    assert verify_manifest(_signed({"version": "1"}, priv), pub2) is None


def test_is_newer():
    assert is_newer({"version": "2"}, "1") is True
    assert is_newer({"version": "1"}, "1") is False
    assert is_newer({"version": ""}, None) is False


# -- bundle application ------------------------------------------------------
def test_apply_bundle_extracts_with_matching_hash(tmp_path):
    data = _tar_bytes({"a/b.yaml": b"template"})
    apply_bundle(data, hashlib.sha256(data).hexdigest(), tmp_path / "t")
    assert (tmp_path / "t" / "a" / "b.yaml").read_bytes() == b"template"


def test_apply_bundle_rejects_hash_mismatch(tmp_path):
    data = _tar_bytes({"a.yaml": b"x"})
    with pytest.raises(ValueError, match="hash mismatch"):
        apply_bundle(data, "deadbeef", tmp_path / "t")


def test_apply_bundle_rejects_path_traversal(tmp_path):
    evil = _tar_bytes({"../escape.yaml": b"x"})
    with pytest.raises(ValueError, match="unsafe path"):
        apply_bundle(evil, None, tmp_path / "t")


# -- orchestration -----------------------------------------------------------
async def test_run_update_applies_then_skips_when_current(tmp_path):
    priv, pub = generate_keypair()
    bundle = _tar_bytes({"http/x.yaml": b"tpl"})
    manifest = {
        "version": "2026.07.21",
        "sha256": hashlib.sha256(bundle).hexdigest(),
        "templates_url": "https://feed/bundle.tar.gz",
    }
    signed = _signed(manifest, priv)

    async def json_get(url, headers):
        return signed

    async def bytes_get(url):
        return bundle

    mongo = FakeMongo()
    dest = tmp_path / "templates"

    r1 = await run_update(
        mongo=mongo,
        feed_url="https://feed",
        license_token=None,
        public_key_pem=pub,
        dest_dir=str(dest),
        json_get=json_get,
        bytes_get=bytes_get,
    )
    assert r1["applied"] is True and r1["version"] == "2026.07.21"
    assert (dest / "http" / "x.yaml").exists()

    # second run with the same manifest → no re-apply
    r2 = await run_update(
        mongo=mongo,
        feed_url="https://feed",
        license_token=None,
        public_key_pem=pub,
        dest_dir=str(dest),
        json_get=json_get,
        bytes_get=bytes_get,
    )
    assert r2["applied"] is False and r2["reason"] == "already current"


async def test_run_update_ignores_unsigned_manifest(tmp_path):
    _priv, pub = generate_keypair()

    async def json_get(url, headers):
        return {"manifest": {"version": "9"}, "signature": "not-valid"}

    async def bytes_get(url):
        raise AssertionError("must not download an unverified bundle")

    r = await run_update(
        mongo=FakeMongo(),
        feed_url="https://feed",
        license_token=None,
        public_key_pem=pub,
        dest_dir=str(tmp_path),
        json_get=json_get,
        bytes_get=bytes_get,
    )
    assert r["applied"] is False and r["reason"] == "invalid signature"
