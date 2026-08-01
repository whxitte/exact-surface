"""Control-plane HTTP service (vendor-hosted). Tiny, stateless, license-gated.

Run it wherever you host your control plane:

    EXACTSURFACE_CP_PRIVATE_KEY_FILE=./license-keys/private.pem \
    EXACTSURFACE_CP_PUBLIC_KEY_FILE=./license-keys/public.pem \
    EXACTSURFACE_CP_STORE=./cp/licenses.json \
    EXACTSURFACE_CP_MANIFEST=./cp/bundle_manifest.json \
    uvicorn control_plane.server:app --port 8800

Endpoints:
* ``POST /v1/license/refresh`` — a customer instance sends its current token; if the
  subscription is current in the store, it gets a freshly-signed token extended up to
  ``paid_until`` (recurring enforcement). Suspended/lapsed → 402 (instance stays on its
  current token and goes read-only when it expires).
* ``GET  /v1/updates/manifest`` — license-gated feed of the latest signed template/tool
  bundle. Lapsed → 402, so a non-subscriber can never pull fresh detections.

The two enforcement decisions (`renew`, `manifest_response`) are pure functions so they
are unit-tested without a running server.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from control_plane.store import LicenseStore
from core.license import (
    Entitlements,
    LicenseError,
    sign_blob,
    sign_license,
    verify_license,
)
from core.models import Plan

ROLLING_DAYS = 35  # a refreshed token always sits ~this far ahead, capped at paid_until


# -- pure decisions (unit-tested) --------------------------------------------
def renew(
    store: LicenseStore,
    token: str,
    *,
    private_key_pem: str,
    public_key_pem: str,
    now: datetime | None = None,
) -> tuple[int, dict]:
    """Decide a refresh. Returns (http_status, body)."""
    now = now or datetime.now(UTC)
    try:
        ent = verify_license(token, public_key_pem)
    except LicenseError as exc:
        return 400, {"detail": f"invalid token: {exc}"}
    record = store.get(ent.license_id)
    if record is None:
        return 404, {"detail": "unknown license"}
    if not record.is_current(now):
        return 402, {"detail": "subscription is not current — renew to continue"}

    new_exp = min(record.paid_until_dt(), now + timedelta(days=ROLLING_DAYS))
    renewed = Entitlements(
        license_id=record.license_id,
        customer_id=record.customer_id,
        customer_name=record.customer_name,
        plan=Plan(record.plan),
        max_domains=record.max_domains,
        max_users=None,
        features=frozenset(),
        issued_at=now,
        expires_at=new_exp,
        grace_days=record.grace_days,
    )
    return 200, {"token": sign_license(renewed, private_key_pem)}


def manifest_response(
    store: LicenseStore,
    token: str,
    manifest: dict,
    *,
    private_key_pem: str,
    public_key_pem: str,
    now: datetime | None = None,
) -> tuple[int, dict]:
    """License-gate + sign the update manifest. Returns (http_status, body)."""
    now = now or datetime.now(UTC)
    try:
        ent = verify_license(token, public_key_pem)
    except LicenseError as exc:
        return 400, {"detail": f"invalid token: {exc}"}
    record = store.get(ent.license_id)
    if record is None or not record.is_current(now):
        return 402, {"detail": "subscription is not current — updates are for subscribers"}
    body = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    return 200, {"manifest": manifest, "signature": sign_blob(body, private_key_pem)}


# -- HTTP wiring -------------------------------------------------------------
def _read(env: str) -> str | None:
    if os.environ.get(env):
        return os.environ[env]
    if os.environ.get(f"{env}_FILE"):
        return Path(os.environ[f"{env}_FILE"]).read_text().strip()
    return None


def _load_manifest() -> dict:
    path = os.environ.get("EXACTSURFACE_CP_MANIFEST")
    if path and Path(path).exists():
        return json.loads(Path(path).read_text())
    return {"version": "0", "templates_url": None, "sha256": None, "tool_versions": {}}


def create_app() -> Any:  # pragma: no cover - thin wrapper; logic is tested directly
    from fastapi import Body, FastAPI, Header, Response

    private_key = _read("EXACTSURFACE_CP_PRIVATE_KEY") or ""
    public_key = _read("EXACTSURFACE_CP_PUBLIC_KEY") or ""
    store = LicenseStore(os.environ.get("EXACTSURFACE_CP_STORE", "./cp/licenses.json"))
    app = FastAPI(title="ExactSurface control plane", version="1.0.0")

    def _respond(result: tuple[int, dict]) -> Response:
        status_code, body = result
        return Response(json.dumps(body), status_code=status_code, media_type="application/json")

    @app.post("/v1/license/refresh")
    def refresh(payload: dict = Body(...)) -> Response:
        token = (payload or {}).get("token") or ""
        return _respond(renew(store, token, private_key_pem=private_key, public_key_pem=public_key))

    @app.get("/v1/updates/manifest")
    def updates(x_license: str = Header(default="")) -> Response:
        return _respond(
            manifest_response(
                store,
                x_license,
                _load_manifest(),
                private_key_pem=private_key,
                public_key_pem=public_key,
            )
        )

    @app.get("/healthz")
    def healthz() -> dict:
        return {"ok": True}

    return app


app = (
    create_app()
    if os.environ.get("EXACTSURFACE_CP_PRIVATE_KEY")
    or os.environ.get("EXACTSURFACE_CP_PRIVATE_KEY_FILE")
    else None
)
