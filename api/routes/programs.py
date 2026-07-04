"""Program (domain) CRUD, plus verification, authorization, scan trigger, and reads."""

from __future__ import annotations

import secrets
import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status

from api.deps import (
    Principal,
    clean_doc,
    get_domain_verifier,
    get_mongo_dep,
    get_principal,
    require_program,
)
from api.schemas import (
    AuthorizationCreate,
    ProgramCreate,
    VerifyCheckResponse,
    VerifyRequestResponse,
)
from core.models import Authorization, Program, VerificationMethod
from core.verification import dns_instructions, http_instructions
from db.assets import AssetRepo
from db.audit import ScanRunRepo
from db.authorizations import AuthorizationRepo
from db.deltas import DeltaRepo
from db.endpoints import EndpointRepo
from db.findings import FindingRepo
from db.programs import ProgramRepo
from db.secrets import SecretRepo

router = APIRouter(prefix="/programs", tags=["programs"])


# -- CRUD --------------------------------------------------------------------
@router.get("")
async def list_programs(
    principal: Principal = Depends(get_principal), mongo: Any = Depends(get_mongo_dep)
) -> list[dict]:
    return [clean_doc(d) for d in await ProgramRepo.from_mongo(mongo).list(principal.tenant_id)]


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_program(
    body: ProgramCreate,
    principal: Principal = Depends(get_principal),
    mongo: Any = Depends(get_mongo_dep),
) -> dict:
    program = Program(
        tenant_id=principal.tenant_id,
        program_id="prog_" + uuid.uuid4().hex[:12],
        apex_domain=body.apex_domain.lower().rstrip("."),
        excluded_hosts=body.excluded_hosts,
        excluded_cidrs=body.excluded_cidrs,
    )
    await ProgramRepo.from_mongo(mongo).save(program)
    return clean_doc(program.model_dump(mode="json"))


@router.get("/{program_id}")
async def get_program(program: dict = Depends(require_program)) -> dict:
    return clean_doc(program)


@router.delete("/{program_id}", status_code=status.HTTP_204_NO_CONTENT)
async def disable_program(
    program: dict = Depends(require_program), mongo: Any = Depends(get_mongo_dep)
) -> None:
    await ProgramRepo.from_mongo(mongo).set_enabled(
        program["tenant_id"], program["program_id"], False
    )


# -- domain verification -----------------------------------------------------
@router.post("/{program_id}/verify/request", response_model=VerifyRequestResponse)
async def request_verification(
    method: VerificationMethod = Query(default=VerificationMethod.DNS_TXT),
    program: dict = Depends(require_program),
    mongo: Any = Depends(get_mongo_dep),
) -> VerifyRequestResponse:
    token = "vantari-verify=" + secrets.token_hex(16)
    await ProgramRepo.from_mongo(mongo).set_verification(
        program["tenant_id"], program["program_id"], method.value, token
    )
    apex = program["apex_domain"]
    instr = (
        dns_instructions(apex, token)
        if method == VerificationMethod.DNS_TXT
        else http_instructions(apex, token)
    )
    return VerifyRequestResponse(method=method, token=token, instructions=instr)


@router.post("/{program_id}/verify/check", response_model=VerifyCheckResponse)
async def check_verification(
    program: dict = Depends(require_program),
    mongo: Any = Depends(get_mongo_dep),
    verifier=Depends(get_domain_verifier),
) -> VerifyCheckResponse:
    token = program.get("verification_token")
    method = program.get("verification_method")
    if not token or not method:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "request a challenge first")
    ok = await verifier.verify(program["apex_domain"], method, token)
    if ok:
        await ProgramRepo.from_mongo(mongo).set_verified(
            program["tenant_id"], program["program_id"], True
        )
    return VerifyCheckResponse(verified=ok, detail="verified" if ok else "challenge not found")


# -- authorization -----------------------------------------------------------
@router.post("/{program_id}/authorization", status_code=status.HTTP_201_CREATED)
async def create_authorization(
    body: AuthorizationCreate,
    program: dict = Depends(require_program),
    principal: Principal = Depends(get_principal),
    mongo: Any = Depends(get_mongo_dep),
) -> dict:
    if not program.get("verified"):
        raise HTTPException(
            status.HTTP_409_CONFLICT, "domain must be verified before authorization"
        )
    auth = Authorization(
        tenant_id=principal.tenant_id,
        program_id=program["program_id"],
        authorized_by=principal.user_id or "apikey",
        apex_verified=True,
        verification_method=program.get("verification_method"),
        ip_scope=body.ip_scope,
        tos_version=body.tos_version,
    )
    await AuthorizationRepo.from_mongo(mongo).save(auth)
    return clean_doc(auth.model_dump(mode="json"))


@router.get("/{program_id}/authorization")
async def get_authorization(
    program: dict = Depends(require_program),
    principal: Principal = Depends(get_principal),
    mongo: Any = Depends(get_mongo_dep),
) -> dict:
    doc = await AuthorizationRepo.from_mongo(mongo).get(principal.tenant_id, program["program_id"])
    if not doc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no authorization record")
    return clean_doc(doc)


# -- scan trigger (auth-gated) ----------------------------------------------
@router.post("/{program_id}/scan", status_code=status.HTTP_202_ACCEPTED)
async def trigger_scan(
    program: dict = Depends(require_program),
    principal: Principal = Depends(get_principal),
    mongo: Any = Depends(get_mongo_dep),
) -> dict:
    if not program.get("verified"):
        raise HTTPException(status.HTTP_409_CONFLICT, "verify the domain first")
    auth = await AuthorizationRepo.from_mongo(mongo).get(principal.tenant_id, program["program_id"])
    if not (auth and auth.get("apex_verified") and not auth.get("revoked")):
        raise HTTPException(
            status.HTTP_409_CONFLICT, "a current authorization record is required before scanning"
        )
    # Enqueue is best-effort here; the scheduler/arq wiring owns real execution.
    return {"status": "queued", "program_id": program["program_id"]}


# -- reads -------------------------------------------------------------------
def _reader(repo_cls):
    async def read(
        program: dict = Depends(require_program),
        principal: Principal = Depends(get_principal),
        mongo: Any = Depends(get_mongo_dep),
    ) -> list[dict]:
        docs = await repo_cls.from_mongo(mongo).list(
            principal.tenant_id, program["program_id"], limit=1000
        )
        return [clean_doc(d) for d in docs]

    return read


router.add_api_route("/{program_id}/assets", _reader(AssetRepo), methods=["GET"], tags=["data"])
router.add_api_route(
    "/{program_id}/endpoints", _reader(EndpointRepo), methods=["GET"], tags=["data"]
)
router.add_api_route("/{program_id}/secrets", _reader(SecretRepo), methods=["GET"], tags=["data"])
router.add_api_route("/{program_id}/deltas", _reader(DeltaRepo), methods=["GET"], tags=["data"])
router.add_api_route(
    "/{program_id}/scan-runs", _reader(ScanRunRepo), methods=["GET"], tags=["data"]
)


@router.get("/{program_id}/findings", tags=["data"])
async def list_findings(
    severity: str | None = None,
    state: str | None = None,
    is_new: bool | None = None,
    program: dict = Depends(require_program),
    principal: Principal = Depends(get_principal),
    mongo: Any = Depends(get_mongo_dep),
) -> list[dict]:
    docs = await FindingRepo.from_mongo(mongo).list(
        principal.tenant_id, program["program_id"], is_new=is_new, limit=1000
    )
    if severity:
        docs = [d for d in docs if d.get("severity") == severity]
    if state:
        docs = [d for d in docs if d.get("state") == state]
    return [clean_doc(d) for d in docs]
