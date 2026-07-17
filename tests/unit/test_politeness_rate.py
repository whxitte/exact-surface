"""Scanner-subprocess politeness rate (§3.8b, §7 Phase D exit).

naabu sends its own packets, so the token-bucket limiter cannot intercept them —
the per-target ceiling has to be computed and handed to the tool. These tests pin
that derivation, and prove the port-scan pipeline actually applies it and
publishes it as metrics (the exit gate is "verified by metrics", not asserted).
"""

from __future__ import annotations

import pytest

from core.ratelimit import SUBPROCESS_RATE_CEILING, subprocess_rate_for


def test_per_target_rate_never_exceeds_the_cap():
    cap = 10.0
    for hosts in (1, 2, 5, 30, 99):
        rate = subprocess_rate_for(hosts, cap)
        assert rate / hosts <= cap, f"{hosts} hosts → {rate}/s = {rate / hosts}/s per target"


def test_rate_scales_with_target_count():
    assert subprocess_rate_for(1, 10.0) == 10
    assert subprocess_rate_for(5, 10.0) == 50
    assert subprocess_rate_for(30, 10.0) == 300


def test_aggregate_is_clamped_by_the_ceiling():
    # 10k hosts × 10/s would be 100k pps of our own egress — clamped.
    assert subprocess_rate_for(10_000, 10.0) == SUBPROCESS_RATE_CEILING


def test_zero_or_negative_hosts_is_safe():
    assert subprocess_rate_for(0, 10.0) == 10  # treated as one target
    assert subprocess_rate_for(-5, 10.0) == 10


def test_rate_is_at_least_one():
    # A tiny cap must not produce rate=0 (which would stall the scan entirely).
    assert subprocess_rate_for(1, 0.001) == 1


def test_old_default_would_have_violated_the_cap():
    """Regression marker: naabu's former flat default was 1000 pps — 100x the
    10/s per-target cap for a single-host scan."""
    assert 1000 / 1 > 10.0
    assert subprocess_rate_for(1, 10.0) == 10


# -- the pipeline actually applies it ---------------------------------------
@pytest.mark.asyncio
async def test_port_scan_passes_derived_rate_and_publishes_metrics():
    from core.config import get_settings
    from core.metrics import REGISTRY
    from core.models import Asset
    from core.scope import ProgramScope, ScopeEngine
    from core.tenant import TenantContext
    from db.assets import AssetRepo
    from pipelines.port_scan import run_port_scan
    from tests.fakes import FakeMongo

    engine = ScopeEngine.from_data_file()
    scope = ProgramScope(
        verified_apexes=("customer.com",), authorized_dedicated_cidrs=("45.55.0.0/16",)
    )
    mongo = FakeMongo()
    for i in (1, 2):
        await AssetRepo.from_mongo(mongo).upsert(
            Asset(
                tenant_id="t1",
                program_id="p1",
                fingerprint=f"a{i}",
                hostname=f"h{i}.customer.com",
                resolved_ips=[f"45.55.1.{i}"],
            )
        )

    seen: dict = {}

    async def fake_naabu(hosts, _timeout, *, rate=None):
        seen["hosts"], seen["rate"] = list(hosts), rate
        return []

    await run_port_scan(
        mongo=mongo,
        engine=engine,
        scope=scope,
        tenant=TenantContext(tenant_id="t1"),
        program_id="p1",
        timeout=5,
        naabu=fake_naabu,
    )

    cap = get_settings().global_rate_per_target
    assert len(seen["hosts"]) == 2
    assert seen["rate"] == subprocess_rate_for(2, cap)
    # per-target stays within the cap — the property the exit gate asks for
    assert seen["rate"] / len(seen["hosts"]) <= cap

    rendered = REGISTRY.render()
    # Labelled tool=naabu now (one metric family for every subprocess, ADR-0013).
    assert 'vantari_subprocess_per_target_pps{tool="naabu"}' in rendered
    assert "vantari_politeness_rate_limit_pps" in rendered
