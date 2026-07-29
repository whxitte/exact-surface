"""Build a template/tool update bundle + its manifest (VENDOR-SIDE).

The update feed is the durable half of the subscription: a lapsed customer keeps
their data but stops receiving fresh detections, and a security scanner running
months-old templates is worthless. This script produces what the feed serves.

    # 1. refresh the templates you want to ship
    nuclei -update-templates -silent
    # 2. pack them, compute the hash, write the manifest
    python -m scripts.build_bundle \
        --templates ~/nuclei-templates \
        --out ./cp-data \
        --base-url https://cp.exactsurface.com/bundles

Writes into --out:
    bundle-<version>.tar.gz   the bundle customers download
    bundle_manifest.json      what the control plane serves (EXACTSURFACE_CP_MANIFEST)

The manifest is *signed by the control plane at request time* (it holds the private
key), so this script never needs the key. Copy both files onto the control-plane data
volume and instances pick the new version up on their next check.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import tarfile
from datetime import UTC, datetime
from pathlib import Path

#: Recon binaries whose versions we record in the manifest, so a customer instance
#: (and you) can see exactly what a bundle corresponds to.
_TOOLS = ("nuclei", "subfinder", "httpx", "naabu", "katana", "tlsx", "dnsx")


def _tool_versions() -> dict[str, str]:
    out: dict[str, str] = {}
    for tool in _TOOLS:
        try:
            res = subprocess.run(  # noqa: S603 - fixed argv, no shell
                [tool, "-version"], capture_output=True, text=True, timeout=15
            )
            text = (res.stdout + res.stderr).strip().splitlines()
            out[tool] = text[-1].strip() if text else "unknown"
        except (OSError, subprocess.SubprocessError):
            out[tool] = "absent"
    return out


def _pack(templates: Path, dest: Path) -> None:
    """Tar+gzip the template tree, skipping VCS noise. Paths are stored relative, so
    the instance extracts them straight into its templates dir."""
    with tarfile.open(dest, "w:gz") as tar:
        for path in sorted(templates.rglob("*")):
            if not path.is_file():
                continue
            rel = path.relative_to(templates)
            if any(part in {".git", ".github", "__pycache__"} for part in rel.parts):
                continue
            tar.add(path, arcname=str(rel))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="scripts.build_bundle", description="Build an update bundle")
    ap.add_argument("--templates", required=True, help="directory of nuclei templates to ship")
    ap.add_argument("--out", required=True, help="output dir (copy onto the control-plane volume)")
    ap.add_argument(
        "--base-url",
        required=True,
        help="public URL prefix the bundle is served from, e.g. https://cp.../bundles",
    )
    ap.add_argument("--version", help="bundle version (default: UTC date, e.g. 2026.07.24)")
    args = ap.parse_args(argv)

    templates = Path(args.templates).expanduser()
    if not templates.is_dir():
        raise SystemExit(f"no such templates directory: {templates}")
    out = Path(args.out).expanduser()
    out.mkdir(parents=True, exist_ok=True)

    version = args.version or datetime.now(UTC).strftime("%Y.%m.%d")
    bundle = out / f"bundle-{version}.tar.gz"
    _pack(templates, bundle)

    digest = hashlib.sha256(bundle.read_bytes()).hexdigest()
    manifest = {
        "version": version,
        "templates_url": f"{args.base_url.rstrip('/')}/{bundle.name}",
        "sha256": digest,
        "tool_versions": _tool_versions(),
        "built_at": datetime.now(UTC).isoformat(),
    }
    (out / "bundle_manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True))

    size_mb = bundle.stat().st_size / 1_048_576
    print(f"bundle:   {bundle}  ({size_mb:.1f} MB)")
    print(f"sha256:   {digest}")
    print(f"manifest: {out / 'bundle_manifest.json'}  (version {version})")
    print("\nNext: copy both files onto the control-plane data volume, e.g.")
    print(f"  docker cp {bundle} exactsurface-control-plane-caddy-1:/srv/bundles/")
    manifest_path = out / "bundle_manifest.json"
    print(f"  docker cp {manifest_path} exactsurface-control-plane-control-plane-1:/data/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
