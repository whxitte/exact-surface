"""Enqueue-time authorization gate at the pipeline layer (§5d, §9b, §9e).

The API returns 409 without an authorization record; this proves the *pipeline
entrypoint itself* refuses — so a job that reached the worker by any path (a
stale queued job, a direct call) still cannot scan a program that lacks a
current authorization. This is the CFAA/CMA defensibility control: no scan
without a stored, current authorization artifact.
"""

from __future__ import annotations

import asyncio

import pytest

from core.errors import AuthorizationRequired
from core.models import Program
from core.scope import ScopeEngine
from core.tenant import TenantContext
from db.programs import ProgramRepo
from pipelines.orchestrate import run_program
from tests.fakes import FakeMongo

ENGINE = ScopeEngine.from_data_file()


def _run(coro):
    return asyncio.run(coro)


def _seed_program(fake, *, tenant_id="t_demo", pid="prog_z", verified=True):
    _run(
        ProgramRepo.from_mongo(fake).save(
            Program(
                tenant_id=tenant_id,
                program_id=pid,
                apex_domain="customer.com",
                verified=verified,
                enabled=True,
            )
        )
    )


def test_run_program_refuses_without_authorization():
    fake = FakeMongo()
    _seed_program(fake)
    with pytest.raises(AuthorizationRequired):
        _run(
            run_program(
                mongo=fake,
                engine=ENGINE,
                tenant=TenantContext(tenant_id="t_demo"),
                program_id="prog_z",
                timeout=5,
                force=True,
            )
        )


def test_run_program_refuses_for_unknown_program():
    fake = FakeMongo()
    with pytest.raises(AuthorizationRequired):
        _run(
            run_program(
                mongo=fake,
                engine=ENGINE,
                tenant=TenantContext(tenant_id="t_demo"),
                program_id="does_not_exist",
                timeout=5,
                force=True,
            )
        )


def test_run_program_skips_paused_without_force():
    """A paused (monitoring-off) program is skipped on automated runs even before
    the authorization check — a queued job from before the pause does no work."""
    fake = FakeMongo()
    _seed_program(fake, pid="prog_paused")
    _run(
        fake.collection("programs").update_one(
            {"program_id": "prog_paused"}, {"$set": {"enabled": False}}
        )
    )
    out = _run(
        run_program(
            mongo=fake,
            engine=ENGINE,
            tenant=TenantContext(tenant_id="t_demo"),
            program_id="prog_paused",
            timeout=5,
            force=False,
        )
    )
    assert out.get("skipped") is True
