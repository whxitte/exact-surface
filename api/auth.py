"""Authentication primitives: password hashing, JWT, API keys (§9).

* Passwords: bcrypt (direct — the passlib wrapper is broken with bcrypt 4.x).
* Sessions: HS256 JWT signed with the rotating ``jwt_secret``.
* API keys: shown once, stored only as a SHA-256 hash (never recoverable).
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime, timedelta

import bcrypt
from jose import JWTError, jwt

from core.config import get_settings
from core.errors import ExactSurfaceError

_MAX_BCRYPT_BYTES = 72  # bcrypt hard limit; longer inputs must be truncated


class InvalidToken(ExactSurfaceError):
    pass


# -- passwords ---------------------------------------------------------------
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode()[:_MAX_BCRYPT_BYTES], bcrypt.gensalt(rounds=12)).decode()


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode()[:_MAX_BCRYPT_BYTES], password_hash.encode())
    except (ValueError, TypeError):
        return False


# -- JWT ---------------------------------------------------------------------
def create_access_token(*, user_id: str, tenant_id: str, role: str, ttl: int | None = None) -> str:
    settings = get_settings()
    now = datetime.now(UTC)
    payload = {
        "sub": user_id,
        "tenant_id": tenant_id,
        "role": role,
        "iat": now,
        "exp": now + timedelta(seconds=ttl or settings.jwt_ttl_seconds),
    }
    return jwt.encode(
        payload, settings.jwt_secret.get_secret_value(), algorithm=settings.jwt_algorithm
    )


def decode_token(token: str) -> dict:
    settings = get_settings()
    try:
        return jwt.decode(
            token, settings.jwt_secret.get_secret_value(), algorithms=[settings.jwt_algorithm]
        )
    except JWTError as exc:
        raise InvalidToken(str(exc)) from exc


# -- API keys ----------------------------------------------------------------
def hash_api_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode()).hexdigest()


def generate_api_key() -> tuple[str, str, str]:
    """Return ``(raw_key, key_hash, prefix)``. The raw key is shown to the user once."""
    raw = "vnt_" + secrets.token_urlsafe(32)
    return raw, hash_api_key(raw), raw[:12]
