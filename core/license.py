"""Self-hosted subscription licensing (§ commercial / self-hosted model).

Vantari ships as an image the customer runs in their own infrastructure, on a monthly
subscription. This module is the enforcement core: a **cryptographically signed license**
that the running instance verifies against an embedded public key, and a **fail-closed
read-only degrade** once the subscription lapses past its grace window.

Honest threat model (self-hosted software runs on the customer's machine):

* The signature (Ed25519) means a customer **cannot forge a license, extend the expiry,
  or change the plan** — only the holder of the private key (you) can mint one. This
  defeats every non-developer bypass, which is ~99% of customers.
* Enforcement is **fail-closed**: a missing, malformed, wrong-key, expired-past-grace, or
  clock-rolled-back license all resolve to **read-only**. There is no "fail open".
* Enforcement is applied **server-side at every value gate** (scan, 403-bypass,
  add-domain, scheduler), not one flippable flag — so patching one check doesn't unlock.
* What this canNOT stop: an engineer with the source and root on their own box patching
  the verification out and rebuilding the image. No self-hosted product prevents that.
  The backstops are the **license contract** (breach = legal recourse), the fact that
  their build is watermarked to them, and — decisively — the **update stream**
  (new templates/tools/patches) which is gated on *your* server and is genuinely
  unbypassable. A stale security product is worthless within weeks, so renewal is
  self-enforcing.

This module is pure and offline-testable: signing, verification, and state evaluation
take their inputs explicitly (keys, token, clock, clock-floor). Wiring lives in
``core.entitlements`` (runtime holder), ``api.deps`` (the guard), the scan routes, and
``taskqueue`` (the scheduler skip).
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum

from core.models import Plan

TOKEN_PREFIX = "vlic1"  # noqa: S105 - a format tag, not a secret; versioned for evolution


class LicenseError(Exception):
    """Raised when a license token is malformed or its signature is invalid."""


class LicenseStatus(str, Enum):
    ACTIVE = "active"  # within the paid period
    GRACE = "grace"  # expired, but inside the grace window — still full function
    EXPIRED = "expired"  # past grace → read-only
    INVALID = "invalid"  # malformed / bad signature / wrong key
    MISSING = "missing"  # no license supplied while enforcement is on
    TAMPERED = "tampered"  # system clock rolled back below the recorded high-water mark
    UNLICENSED = "unlicensed"  # enforcement disabled (dev) — full function, no license


#: Statuses that still permit scanning and other state-generating actions.
_FULL_FUNCTION = frozenset({LicenseStatus.ACTIVE, LicenseStatus.GRACE, LicenseStatus.UNLICENSED})


@dataclass(frozen=True)
class Entitlements:
    """What a valid license grants. Mirrors the §13 plan model plus subscription dates."""

    license_id: str
    customer_id: str
    customer_name: str
    plan: Plan
    max_domains: int | None  # None = unlimited
    max_users: int | None
    features: frozenset[str]  # optional-module entitlements (empty = plan default)
    issued_at: datetime
    expires_at: datetime
    grace_days: int


@dataclass(frozen=True)
class LicenseState:
    """The evaluated runtime state the app enforces against."""

    status: LicenseStatus
    read_only: bool
    reason: str
    entitlements: Entitlements | None
    #: end of grace (expires_at + grace_days) when there is a license, else None
    hard_expiry: datetime | None = None

    @property
    def full_function(self) -> bool:
        return self.status in _FULL_FUNCTION and not self.read_only


# -- codec -------------------------------------------------------------------
def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(txt: str) -> bytes:
    pad = "=" * (-len(txt) % 4)
    return base64.urlsafe_b64decode(txt + pad)


def _isoformat(dt: datetime) -> str:
    return dt.astimezone(UTC).isoformat()


def _parse_dt(value: object) -> datetime:
    if not isinstance(value, str):
        raise LicenseError("license date is not a string")
    try:
        dt = datetime.fromisoformat(value)
    except ValueError as exc:
        raise LicenseError(f"license date not ISO-8601: {value!r}") from exc
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


# -- signing (private key — the minting CLI only) ----------------------------
def generate_keypair() -> tuple[str, str]:
    """Return (private_pem, public_pem) for a fresh Ed25519 keypair. The private key
    stays with you (the minting CLI); the public key is baked into the image."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv = Ed25519PrivateKey.generate()
    private_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = (
        priv.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    return private_pem, public_pem


def sign_license(entitlements: Entitlements, private_key_pem: str) -> str:
    """Produce a signed license token. Used only by your offline minting CLI."""
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    claims = {
        "v": 1,
        "lid": entitlements.license_id,
        "cid": entitlements.customer_id,
        "cname": entitlements.customer_name,
        "plan": entitlements.plan.value,
        "max_domains": entitlements.max_domains,
        "max_users": entitlements.max_users,
        "features": sorted(entitlements.features),
        "iat": _isoformat(entitlements.issued_at),
        "exp": _isoformat(entitlements.expires_at),
        "grace_days": entitlements.grace_days,
    }
    payload = _b64url_encode(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode())
    priv = load_pem_private_key(private_key_pem.encode(), password=None)
    signature = priv.sign(payload.encode("ascii"))  # type: ignore[attr-defined]
    return f"{TOKEN_PREFIX}.{payload}.{_b64url_encode(signature)}"


# -- generic blob signing (reused by the update feed's signed bundles) -------
def sign_blob(data: bytes, private_key_pem: str) -> str:
    """Sign arbitrary bytes with the Ed25519 private key → base64url signature. Used to
    sign update-bundle manifests so a customer instance trusts only content you signed."""
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    priv = load_pem_private_key(private_key_pem.encode(), password=None)
    return _b64url_encode(priv.sign(data))  # type: ignore[attr-defined]


def verify_blob(data: bytes, signature_b64: str, public_key_pem: str) -> bool:
    """Return True iff *signature_b64* is a valid Ed25519 signature of *data*."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    try:
        pub = load_pem_public_key(public_key_pem.encode())
        if not isinstance(pub, Ed25519PublicKey):
            return False
        pub.verify(_b64url_decode(signature_b64), data)
        return True
    except Exception:  # noqa: BLE001 - any failure (bad sig, bad key, bad b64) = invalid
        return False


# -- verification (public key — the running instance) ------------------------
def verify_license(token: str, public_key_pem: str) -> Entitlements:
    """Verify *token*'s signature with *public_key_pem* and return its entitlements.

    Raises :class:`LicenseError` on any malformation or signature mismatch. Verifying the
    signature is the whole security boundary — a customer cannot alter a single claim
    (expiry, plan, domain count) without invalidating it, and cannot re-sign without the
    private key.
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    if not token or token.count(".") != 2:
        raise LicenseError("malformed license token")
    prefix, payload_b64, sig_b64 = token.split(".")
    if prefix != TOKEN_PREFIX:
        raise LicenseError(f"unsupported license version: {prefix!r}")
    try:
        pub = load_pem_public_key(public_key_pem.encode())
    except Exception as exc:  # noqa: BLE001
        raise LicenseError("invalid license public key configured") from exc
    if not isinstance(pub, Ed25519PublicKey):
        raise LicenseError("license public key is not Ed25519")
    try:
        pub.verify(_b64url_decode(sig_b64), payload_b64.encode("ascii"))
    except InvalidSignature as exc:
        raise LicenseError("license signature does not verify") from exc

    try:
        claims = json.loads(_b64url_decode(payload_b64))
    except (ValueError, json.JSONDecodeError) as exc:
        raise LicenseError("license payload is not valid JSON") from exc

    try:
        return Entitlements(
            license_id=str(claims["lid"]),
            customer_id=str(claims["cid"]),
            customer_name=str(claims.get("cname", "")),
            plan=Plan(claims["plan"]),
            max_domains=claims.get("max_domains"),
            max_users=claims.get("max_users"),
            features=frozenset(claims.get("features") or ()),
            issued_at=_parse_dt(claims["iat"]),
            expires_at=_parse_dt(claims["exp"]),
            grace_days=int(claims.get("grace_days", 0)),
        )
    except (KeyError, ValueError) as exc:
        raise LicenseError(f"license missing/invalid claim: {exc}") from exc


# -- state evaluation --------------------------------------------------------
def evaluate(
    entitlements: Entitlements | None,
    *,
    now: datetime,
    clock_floor: datetime | None = None,
    error: LicenseError | None = None,
    enforced: bool = True,
) -> LicenseState:
    """Turn entitlements + the clock into the enforced runtime state.

    * ``enforced=False`` (dev) → always full function, no license needed.
    * ``clock_floor`` is the persisted high-water-mark of observed time; if ``now`` is
      meaningfully **before** it, the system clock was rolled back → tampered → read-only.
    * Past ``expires_at`` but within ``grace_days`` → GRACE (still full function, so a
      late payment never silently kills a security team's monitoring).
    * Past grace → EXPIRED → read-only.
    """
    if not enforced:
        return LicenseState(LicenseStatus.UNLICENSED, False, "enforcement disabled", None)
    if error is not None:
        return LicenseState(LicenseStatus.INVALID, True, str(error), None)
    if entitlements is None:
        return LicenseState(LicenseStatus.MISSING, True, "no license configured", None)

    # Clock-rollback guard: allow a small skew for NTP jitter, but a jump back below the
    # last time we've ever seen means the clock was moved to dodge expiry.
    if clock_floor is not None and now < clock_floor - timedelta(hours=6):
        return LicenseState(
            LicenseStatus.TAMPERED,
            True,
            "system clock is earlier than last recorded time — refusing to trust it",
            entitlements,
        )

    hard_expiry = entitlements.expires_at + timedelta(days=max(0, entitlements.grace_days))
    if now <= entitlements.expires_at:
        return LicenseState(
            LicenseStatus.ACTIVE, False, "subscription active", entitlements, hard_expiry
        )
    if now <= hard_expiry:
        return LicenseState(
            LicenseStatus.GRACE,
            False,
            f"subscription expired {entitlements.expires_at.date()} — in grace, renew soon",
            entitlements,
            hard_expiry,
        )
    return LicenseState(
        LicenseStatus.EXPIRED,
        True,
        f"subscription expired {entitlements.expires_at.date()} — read-only until renewed",
        entitlements,
        hard_expiry,
    )
