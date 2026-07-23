"""Vantari license minting CLI (§ commercial / self-hosted).

Run this OFFLINE, on your own machine — it holds the Ed25519 **private key** that mints
subscriptions. The private key must never ship in the image; only the matching public
key is baked into the build (it can verify, never sign).

    # one-time: create your signing keypair
    python -m scripts.license keygen --out-dir ./license-keys
    #   → license-keys/private.pem  (KEEP SECRET — this is your money printer)
    #   → license-keys/public.pem   (bake into the image: VANTARI_LICENSE_PUBLIC_KEY)

    # issue a customer a 1-month Business subscription (25 domains)
    python -m scripts.license issue \
        --private-key ./license-keys/private.pem \
        --customer "Acme Corp" --plan business --domains 25 --months 1 --out acme.vlic

    # inspect / verify a token against the public key
    python -m scripts.license inspect --public-key ./license-keys/public.pem "$(cat acme.vlic)"

Give the customer the token (a mounted file or the VANTARI_LICENSE env var) at deploy
time. Renew by issuing a new token with a later expiry and handing it over (or serving
it from the online-refresh endpoint).
"""

from __future__ import annotations

import argparse
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from core.license import (
    Entitlements,
    LicenseError,
    LicenseStatus,
    evaluate,
    generate_keypair,
    sign_license,
    verify_license,
)
from core.models import Plan

# Plan → default domain cap (matches core.plans.PLAN_LIMITS); --domains overrides.
_PLAN_DEFAULT_DOMAINS = {"free": 1, "pro": 5, "business": 25, "enterprise": None}


def _cmd_keygen(args: argparse.Namespace) -> int:
    private_pem, public_pem = generate_keypair()
    if args.out_dir:
        out = Path(args.out_dir)
        out.mkdir(parents=True, exist_ok=True)
        (out / "private.pem").write_text(private_pem)
        (out / "public.pem").write_text(public_pem)
        (out / "private.pem").chmod(0o600)
        print(f"wrote {out/'private.pem'} (KEEP SECRET) and {out/'public.pem'}")
    else:
        print("# --- PRIVATE KEY (keep secret) ---")
        print(private_pem)
        print("# --- PUBLIC KEY (bake into image) ---")
        print(public_pem)
    return 0


def _cmd_issue(args: argparse.Namespace) -> int:
    private_pem = Path(args.private_key).read_text()
    plan = Plan(args.plan)
    domains = args.domains if args.domains is not None else _PLAN_DEFAULT_DOMAINS[args.plan]
    now = datetime.now(UTC)
    ent = Entitlements(
        license_id=args.license_id or ("lic_" + uuid.uuid4().hex[:16]),
        customer_id=args.customer_id or ("cus_" + uuid.uuid4().hex[:12]),
        customer_name=args.customer,
        plan=plan,
        max_domains=domains,  # None = unlimited
        max_users=args.users,
        features=frozenset(f.strip() for f in (args.features or "").split(",") if f.strip()),
        issued_at=now,
        expires_at=now + timedelta(days=round(args.months * 30)),
        grace_days=args.grace,
    )
    token = sign_license(ent, private_pem)
    if args.out:
        Path(args.out).write_text(token)
        print(f"wrote license to {args.out}")
    else:
        print(token)
    # Optionally register the subscription in the control-plane store so the online
    # refresh endpoint will renew this customer up to the paid-through date.
    if args.store:
        from control_plane.store import LicenseRecord, LicenseStore

        LicenseStore(args.store).upsert(
            LicenseRecord(
                license_id=ent.license_id,
                customer_id=ent.customer_id,
                customer_name=ent.customer_name,
                plan=plan.value,
                max_domains=domains,
                paid_until=ent.expires_at.isoformat(),
                status="active",
                grace_days=args.grace,
            )
        )
        print(f"# registered in control-plane store: {args.store}", file=sys.stderr)
    exp = ent.expires_at.date()
    cap = "unlimited" if domains is None else domains
    print(
        f"# {ent.customer_name}: {plan.value}, {cap} domains, "
        f"expires {exp} (+{args.grace}d grace), id {ent.license_id}",
        file=sys.stderr,
    )
    return 0


def _cmd_inspect(args: argparse.Namespace) -> int:
    public_pem = Path(args.public_key).read_text()
    try:
        ent = verify_license(args.token, public_pem)
    except LicenseError as exc:
        print(f"INVALID: {exc}")
        return 1
    st = evaluate(ent, now=datetime.now(UTC))
    print("signature: VALID")
    print(f"customer:  {ent.customer_name} ({ent.customer_id})")
    print(f"license:   {ent.license_id}")
    print(f"plan:      {ent.plan.value}  domains={ent.max_domains}  users={ent.max_users}")
    print(f"features:  {', '.join(sorted(ent.features)) or '(plan default)'}")
    print(f"issued:    {ent.issued_at.isoformat()}")
    print(f"expires:   {ent.expires_at.isoformat()}  (+{ent.grace_days}d grace)")
    print(f"state now: {st.status.value}  read_only={st.read_only}")
    return 0 if st.status in (LicenseStatus.ACTIVE, LicenseStatus.GRACE) else 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="scripts.license", description="Vantari license minting")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_key = sub.add_parser("keygen", help="generate an Ed25519 signing keypair")
    p_key.add_argument("--out-dir", help="write private.pem + public.pem here (else stdout)")
    p_key.set_defaults(func=_cmd_keygen)

    p_iss = sub.add_parser("issue", help="mint a signed subscription license")
    p_iss.add_argument("--private-key", required=True, help="path to your private.pem")
    p_iss.add_argument("--customer", required=True, help="customer display name")
    p_iss.add_argument("--customer-id", help="stable customer id (default: generated)")
    p_iss.add_argument("--license-id", help="license id (default: generated)")
    p_iss.add_argument(
        "--plan", choices=list(_PLAN_DEFAULT_DOMAINS), default="business", help="plan tier"
    )
    p_iss.add_argument("--domains", type=int, help="max domains (omit → the plan's default)")
    p_iss.add_argument("--users", type=int, help="max users (default: unlimited)")
    p_iss.add_argument("--features", help="comma-separated optional-module entitlements")
    p_iss.add_argument("--months", type=float, default=1.0, help="subscription length in months")
    p_iss.add_argument("--grace", type=int, default=14, help="grace days after expiry (default 14)")
    p_iss.add_argument("--out", help="write the token to this file (else stdout)")
    p_iss.add_argument("--store", help="also register in this control-plane store (online refresh)")
    p_iss.set_defaults(func=_cmd_issue)

    p_ins = sub.add_parser("inspect", help="verify + print a license token")
    p_ins.add_argument("--public-key", required=True, help="path to public.pem")
    p_ins.add_argument("token", help="the license token")
    p_ins.set_defaults(func=_cmd_inspect)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
