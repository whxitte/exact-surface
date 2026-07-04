"""Per-tenant rate limiting (slowapi).

Limits are keyed by tenant (from the JWT) when authenticated, falling back to the
client IP for pre-auth endpoints — so a noisy tenant is throttled as a tenant, not
merely per-IP (§9 "rate limits per tenant, not per IP").
"""

from __future__ import annotations

from slowapi import Limiter
from slowapi.util import get_remote_address
from starlette.requests import Request

from api.auth import InvalidToken, decode_token


def tenant_or_ip_key(request: Request) -> str:
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        try:
            return "t:" + decode_token(auth[7:])["tenant_id"]
        except (InvalidToken, KeyError):
            pass
    api_key = request.headers.get("x-api-key")
    if api_key:
        return "k:" + api_key[:16]
    return "ip:" + get_remote_address(request)


limiter = Limiter(key_func=tenant_or_ip_key, default_limits=[])
