"""Seed a demo tenant + verified program + sample findings for local dev.

Importable ``seed(mongo)`` (tested against the in-memory fake) and a ``__main__``
that seeds a real MongoDB. Lets the frontend show a populated dashboard without
running a live scan.
"""

from __future__ import annotations

import asyncio
from typing import Any

from api.auth import hash_password
from core.hashing import asset_fingerprint, endpoint_fingerprint, finding_fingerprint
from core.models import (
    Asset,
    Authorization,
    Endpoint,
    ExposedSecret,
    Finding,
    Program,
    Role,
    Severity,
    Tenant,
    User,
    VerificationMethod,
)
from db.assets import AssetRepo
from db.authorizations import AuthorizationRepo
from db.endpoints import EndpointRepo
from db.findings import FindingRepo
from db.programs import ProgramRepo
from db.secrets import SecretRepo
from db.tenants import TenantRepo
from db.users import UserRepo

DEMO_EMAIL = "demo@vantari.io"
DEMO_PASSWORD = "demo-password-123"  # noqa: S105 - local dev seed only
APEX = "example.com"


async def seed(
    mongo: Any, *, email: str = DEMO_EMAIL, password: str = DEMO_PASSWORD, apex: str = APEX
) -> dict:
    tid, uid, pid = "t_demo", "u_demo", "prog_demo"

    await TenantRepo.from_mongo(mongo).create(Tenant(tenant_id=tid, name="Demo Co"))
    await UserRepo.from_mongo(mongo).create(
        User(
            tenant_id=tid,
            user_id=uid,
            email=email,
            password_hash=hash_password(password),
            role=Role.OWNER,
        )
    )
    await ProgramRepo.from_mongo(mongo).save(
        Program(
            tenant_id=tid,
            program_id=pid,
            apex_domain=apex,
            verified=True,
            verification_method=VerificationMethod.DNS_TXT,
        )
    )
    await AuthorizationRepo.from_mongo(mongo).save(
        Authorization(tenant_id=tid, program_id=pid, authorized_by=uid, apex_verified=True)
    )

    hosts = [("www." + apex, ["93.184.216.34"], False), ("staging." + apex, ["45.55.1.1"], True)]
    for host, ips, ephemeral in hosts:
        await AssetRepo.from_mongo(mongo).upsert(
            Asset(
                tenant_id=tid,
                program_id=pid,
                fingerprint=asset_fingerprint(pid, host),
                hostname=host,
                resolved_ips=ips,
                is_ephemeral=ephemeral,
                source="seed",
            )
        )
    await EndpointRepo.from_mongo(mongo).upsert(
        Endpoint(
            tenant_id=tid,
            program_id=pid,
            fingerprint=endpoint_fingerprint(pid, "GET", f"https://www.{apex}"),
            url=f"https://www.{apex}",
            status_code=200,
            title="Example",
            tech=["nginx"],
        )
    )
    await FindingRepo.from_mongo(mongo).upsert(
        Finding(
            tenant_id=tid,
            program_id=pid,
            fingerprint=finding_fingerprint(pid, "exposed-env", f"https://staging.{apex}/.env"),
            check_id="exposed-env",
            module="nuclei",
            location=f"https://staging.{apex}/.env",
            name="Exposed .env file",
            severity=Severity.CRITICAL,
            description="Environment file served at web root.",
        )
    )
    await SecretRepo.from_mongo(mongo).upsert(
        ExposedSecret(
            tenant_id=tid,
            program_id=pid,
            fingerprint="seed-secret",
            kind="aws_access_key",
            masked="AKIA••••••••LE",
            value_hash="seedhash",
            source_locator=f"https://staging.{apex}/static/main.js",
            severity=Severity.HIGH,
        )
    )
    return {"tenant_id": tid, "program_id": pid, "email": email, "password": password}


async def main() -> None:  # pragma: no cover - hits a real DB
    from db.mongo import get_mongo

    mongo = get_mongo()
    await mongo.connect()
    await mongo.ensure_indexes()
    result = await seed(mongo)
    await mongo.close()
    print(f"seeded demo tenant: {result}")


if __name__ == "__main__":  # pragma: no cover
    asyncio.run(main())
