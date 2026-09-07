"""Symmetric encryption for tenant secrets stored at rest (§9c).

Operator-supplied API keys (GitHub token, Google CSE key, …) must be recoverable
to actually call the upstream API, so unlike exposed-secret *evidence* (which we
only ever HMAC-hash) these are encrypted with a reversible cipher.

The Fernet key is *derived* from ``secret_hash_key`` (SHA-256 → 32 bytes →
url-safe base64), so there is no extra key material to provision: whatever already
protects the HMAC key protects this. Rotating ``secret_hash_key`` invalidates all
stored ciphertext — the affected integrations simply have to be re-entered.
"""

from __future__ import annotations

import base64
from functools import lru_cache

from core.config import get_settings


@lru_cache(maxsize=1)
def _fernet():
    from cryptography.fernet import Fernet

    key = base64.urlsafe_b64encode(get_settings().secret_hash_key_bytes())
    return Fernet(key)


def encrypt(plaintext: str) -> str:
    """Encrypt *plaintext* to an opaque url-safe token safe to persist."""
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt(token: str) -> str | None:
    """Decrypt a token from :func:`encrypt`. Returns ``None`` if it can't be
    decrypted (tampered, or the key was rotated) rather than raising."""
    from cryptography.fernet import InvalidToken

    try:
        return _fernet().decrypt(token.encode()).decode()
    except (InvalidToken, ValueError):
        return None
