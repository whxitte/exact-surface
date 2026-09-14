"""HTTP client for the ExactSurface API, shaped for tool use.

Deliberately small: one class, one method per verb, and errors turned into messages
an agent can act on ("this key lacks the scans:run scope") rather than tracebacks.
"""

from __future__ import annotations

import os
from typing import Any

import httpx


class ExactSurfaceError(Exception):
    """An API refusal or failure, with a message meant to be read by the caller."""


class ExactSurfaceClient:
    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        *,
        verify_tls: bool | None = None,
        timeout: float = 30.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        base_url = base_url or os.environ.get("EXACTSURFACE_URL", "")
        api_key = api_key or os.environ.get("EXACTSURFACE_API_KEY", "")
        if not base_url:
            raise ExactSurfaceError(
                "EXACTSURFACE_URL is not set. Point it at your instance, e.g. "
                "https://exactsurface.example.com"
            )
        if not api_key:
            raise ExactSurfaceError(
                "EXACTSURFACE_API_KEY is not set. Create one under Settings → API keys; "
                "read-only is enough to look around, add scans:run to start scans."
            )
        if verify_tls is None:
            verify_tls = os.environ.get("EXACTSURFACE_VERIFY_TLS", "1") not in ("0", "false", "no")
        # The product frontend proxies /api/* to the API; the API itself is not published.
        # So a deployed instance is addressed as https://host/api, a local dev API as
        # http://localhost:8000. Accept either: append /api unless the URL already ends
        # in it or points at a bare API port.
        root = base_url.rstrip("/")
        if not root.endswith("/api") and not root.rsplit(":", 1)[-1].isdigit():
            root += "/api"
        self._http = httpx.AsyncClient(
            base_url=root,
            headers={"X-API-Key": api_key, "User-Agent": "exactsurface-mcp"},
            verify=verify_tls,
            timeout=timeout,
            transport=transport,
        )

    async def aclose(self) -> None:
        await self._http.aclose()

    async def get(self, path: str, **params: Any) -> Any:
        return await self._call(
            "GET", path, params={k: v for k, v in params.items() if v is not None}
        )

    async def post(self, path: str, body: Any = None, **params: Any) -> Any:
        return await self._call(
            "POST", path, json=body, params={k: v for k, v in params.items() if v is not None}
        )

    async def _call(self, method: str, path: str, **kw: Any) -> Any:
        try:
            r = await self._http.request(method, path, **kw)
        except httpx.ConnectError as exc:
            raise ExactSurfaceError(
                f"could not reach ExactSurface at {self._http.base_url}: {exc}"
            ) from exc
        except httpx.TimeoutException as exc:
            raise ExactSurfaceError(f"ExactSurface did not answer in time: {exc}") from exc
        if r.status_code == 204:
            return None
        if r.status_code >= 400:
            raise ExactSurfaceError(_explain(r))
        try:
            return r.json()
        except ValueError:
            return r.text


def _explain(r: httpx.Response) -> str:
    """Turn an error response into one sentence the agent can act on."""
    try:
        detail = r.json().get("detail")
    except ValueError:
        detail = r.text[:200]
    if isinstance(detail, dict):
        detail = detail.get("message") or str(detail)
    if r.status_code == 401:
        return "the API key was refused (invalid or revoked). Check EXACTSURFACE_API_KEY."
    if r.status_code == 403:
        # The API's own messages are already precise: which scope is missing, or that
        # the action needs a person. Pass them through.
        return f"refused: {detail}"
    if r.status_code == 404:
        return f"not found: {detail or 'no such program or resource for this key'}"
    if r.status_code == 409:
        return f"not possible right now: {detail}"
    if r.status_code == 422:
        return f"rejected: {detail}"
    if r.status_code == 429:
        return "rate limited by ExactSurface; wait a minute and retry"
    return f"ExactSurface returned {r.status_code}: {detail}"
