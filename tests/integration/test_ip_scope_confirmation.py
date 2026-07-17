"""Worker-side ASN confirmation of the authorization IP scope (§9b step 3, §5d).

The API host has no asnmap (§3.8 keeps it slim), so confirmation runs on the
worker inside ``run_program``: look up the verified apex's announced ASN ranges,
decide each requested CIDR, write the verdict back into the authorization record
(so it is auditable), and build the scope from confirmed entries only.

Fail-safe is the property that matters most here: if asnmap is missing or errors,
nothing may be confirmed — losing ASN data must never *grant* access.
"""

from __future__ import annotations

import asyncio

from core.models import Authorization, IpScopeEntry, Program, VerificationMethod
from core.scope import ScopeEngine
from db.authorizations import AuthorizationRepo
from db.programs import ProgramRepo
from pipelines.orchestrate import build_program_scope, confirm_authorization_ip_scope
from tests.fakes import FakeMongo

ENGINE = ScopeEngine.from_data_file()
TID, PID = "t1", "p1"


def _run(coro):
    return asyncio.run(coro)


def _seed(fake, requested: list[str]) -> tuple[dict, dict]:
    program = Program(tenant_id=TID, program_id=PID, apex_domain="customer.com", verified=True)
    _run(ProgramRepo.from_mongo(fake).save(program))
    auth = Authorization(
        tenant_id=TID,
        program_id=PID,
        authorized_by="u1",
        apex_verified=True,
        verification_method=VerificationMethod.DNS_TXT,
        ip_scope=[
            IpScopeEntry(
                cidr=c, ip_class="public", action_set=["http_probe"], confirmed_via="pending"
            )
            for c in requested
        ],
    )
    _run(AuthorizationRepo.from_mongo(fake).save(auth))
    return program.model_dump(mode="json"), auth.model_dump(mode="json")


async def _asn_ok(_apex, _timeout):
    return ["45.55.0.0/16"]  # what asnmap reports for the customer's apex


async def _asn_boom(_apex, _timeout):
    raise FileNotFoundError("asnmap: not found")


def test_confirmed_cidr_is_promoted_and_persisted():
    fake = FakeMongo()
    program, auth = _seed(fake, ["45.55.1.0/24", "8.8.8.0/24"])

    updated = _run(
        confirm_authorization_ip_scope(fake, program, auth, engine=ENGINE, asn_ranges=_asn_ok)
    )
    by_cidr = {e["cidr"]: e for e in updated["ip_scope"]}
    assert by_cidr["45.55.1.0/24"]["ip_class"] == "dedicated"
    assert by_cidr["45.55.1.0/24"]["confirmed_via"] == "asnmap:45.55.0.0/16"
    assert by_cidr["8.8.8.0/24"]["ip_class"] != "dedicated"  # not in the apex's ASN

    # §5d: the verdict is recorded on the authorization record itself
    stored = _run(AuthorizationRepo.from_mongo(fake).get(TID, PID))
    assert {e["cidr"]: e["confirmed_via"] for e in stored["ip_scope"]} == {
        "45.55.1.0/24": "asnmap:45.55.0.0/16",
        "8.8.8.0/24": "unconfirmed",
    }

    # and only the confirmed one reaches the scope
    scope = build_program_scope(program, updated)
    assert scope.authorized_dedicated_cidrs == ("45.55.1.0/24",)


def test_asnmap_failure_confirms_nothing():
    """asnmap missing/erroring ⇒ HTTP-layer only. Never fail open."""
    fake = FakeMongo()
    program, auth = _seed(fake, ["45.55.1.0/24"])

    updated = _run(
        confirm_authorization_ip_scope(fake, program, auth, engine=ENGINE, asn_ranges=_asn_boom)
    )
    assert updated["ip_scope"][0]["confirmed_via"] == "unconfirmed"
    assert build_program_scope(program, updated).authorized_dedicated_cidrs == ()


def test_no_requested_cidrs_is_a_noop():
    fake = FakeMongo()
    program, auth = _seed(fake, [])
    updated = _run(
        confirm_authorization_ip_scope(fake, program, auth, engine=ENGINE, asn_ranges=_asn_ok)
    )
    assert updated["ip_scope"] == []
    assert build_program_scope(program, updated).authorized_dedicated_cidrs == ()


def test_reconfirmation_revokes_a_range_the_customer_no_longer_owns():
    """If the ASN stops announcing a range, the next run must drop it — the
    authorization record is re-confirmed every scan, not trusted forever."""
    fake = FakeMongo()
    program, auth = _seed(fake, ["45.55.1.0/24"])
    auth = _run(
        confirm_authorization_ip_scope(fake, program, auth, engine=ENGINE, asn_ranges=_asn_ok)
    )
    assert build_program_scope(program, auth).authorized_dedicated_cidrs == ("45.55.1.0/24",)

    async def _asn_lost(_apex, _timeout):
        return ["203.0.113.0/24"]  # customer no longer announces 45.55/16

    auth = _run(
        confirm_authorization_ip_scope(fake, program, auth, engine=ENGINE, asn_ranges=_asn_lost)
    )
    assert build_program_scope(program, auth).authorized_dedicated_cidrs == ()
