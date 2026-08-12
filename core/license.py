"""Self-hosted product state models."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum

from core.models import Plan



class LicenseError(Exception):
    """Raised when a token is malformed."""


class LicenseStatus(str, Enum):
    ACTIVE = "active"
    GRACE = "grace"
    EXPIRED = "expired"
    INVALID = "invalid"
    MISSING = "missing"
    TAMPERED = "tampered"
    UNLICENSED = "unlicensed"


_FULL_FUNCTION = frozenset({LicenseStatus.ACTIVE, LicenseStatus.GRACE, LicenseStatus.UNLICENSED})


@dataclass(frozen=True)
class Entitlements:
    """What an installation grants."""

    license_id: str
    customer_id: str
    customer_name: str
    plan: Plan
    max_domains: int | None
    max_users: int | None
    features: frozenset[str]
    issued_at: datetime
    expires_at: datetime
    grace_days: int


@dataclass(frozen=True)
class LicenseState:
    """The evaluated runtime state."""

    status: LicenseStatus
    read_only: bool
    reason: str
    entitlements: Entitlements | None
    hard_expiry: datetime | None = None

    @property
    def full_function(self) -> bool:
        return True


def generate_keypair() -> tuple[str, str]:
    """Generate an Ed25519 keypair (priv_pem, pub_pem)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    return priv_pem, pub_pem


def sign_blob(blob: bytes, private_key_pem: str) -> str:
    """Sign arbitrary bytes with an Ed25519 private key."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
    if not isinstance(priv, Ed25519PrivateKey):
        raise LicenseError("private key must be Ed25519")
    sig = priv.sign(blob)
    return base64.urlsafe_b64encode(sig).rstrip(b"=").decode("ascii")


def verify_blob(blob: bytes, signature_b64: str, public_key_pem: str) -> bool:
    """Verify Ed25519 signature of a blob."""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        pub = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        if not isinstance(pub, Ed25519PublicKey):
            return False
        sig = base64.urlsafe_b64decode(signature_b64 + "=" * (-len(signature_b64) % 4))
        pub.verify(sig, blob)
        return True
    except Exception:  # noqa: BLE001
        return False


def evaluate(
    entitlements: Entitlements | None = None,
    *,
    now: datetime | None = None,
    clock_floor: datetime | None = None,
    error: LicenseError | None = None,
    enforced: bool = False,
) -> LicenseState:
    """Always returns full function status for free self-hosted edition."""
    return LicenseState(LicenseStatus.UNLICENSED, False, "Self-hosted free edition", None)
