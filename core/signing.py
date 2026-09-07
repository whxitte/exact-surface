"""Ed25519 detached signatures.

Used to verify update manifests: ``core.updates`` fetches a feed, checks the detached
signature against a pinned public key, and refuses the payload if it does not verify.
That is the only thing standing between a scope-feed or template update and arbitrary
attacker-supplied content, so it is deliberately small and dependency-light.

These functions previously lived in ``core.license``, next to a licence-key checker.
The licensing machinery is gone; signature verification was never part of it and only
shared the file because both happened to use Ed25519.
"""

from __future__ import annotations

import base64


class SignatureError(Exception):
    """Raised when a key is the wrong type or otherwise unusable."""


def generate_keypair() -> tuple[str, str]:
    """Generate an Ed25519 keypair, returned as ``(private_pem, public_pem)``."""
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
    """Sign bytes, returning an unpadded urlsafe-base64 detached signature."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
    if not isinstance(priv, Ed25519PrivateKey):
        raise SignatureError("private key must be Ed25519")
    sig = priv.sign(blob)
    return base64.urlsafe_b64encode(sig).rstrip(b"=").decode("ascii")


def verify_blob(blob: bytes, signature_b64: str, public_key_pem: str) -> bool:
    """Verify a detached signature. Returns False for *any* failure.

    Deliberately total: a malformed key, malformed base64 and a genuinely bad signature
    are all "did not verify", because every caller does the same thing with each of them
    — refuse the payload. Distinguishing them here would only invite a caller to treat
    one as recoverable.
    """
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
