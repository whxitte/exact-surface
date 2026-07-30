"""Subdomain permutation (modules.recon.alterx) — wiring a previously dead tool.

alterx was installed in the scanning image but never called. It now feeds ingest, with
one rule that matters: permutations are *guesses*, so nothing is persisted unless DNS
confirms it. These pin that, and that a missing binary degrades rather than fails.
"""

from __future__ import annotations

from modules.recon.alterx import MAX_PERMUTATIONS, permute


async def test_generates_and_filters_candidates():
    async def fake(_bin, _args, timeout=None, stdin=None):
        # alterx echoes inputs when enriching; those must not be re-emitted.
        return ["api.acme.com", "api-dev.acme.com", "api-staging.acme.com", ""]

    out = await permute(["api.acme.com"], 10.0, runner=fake)
    assert out == ["api-dev.acme.com", "api-staging.acme.com"]


async def test_missing_binary_is_not_fatal():
    """Permutation is an enhancement — losing it must never cost us the subdomains
    passive discovery already found."""
    from modules.exec import ToolNotFound

    async def missing(*_a, **_kw):
        raise ToolNotFound("alterx")

    assert await permute(["api.acme.com"], 10.0, runner=missing) == []


async def test_empty_input_short_circuits():
    calls = []

    async def spy(*a, **kw):
        calls.append(a)
        return []

    assert await permute([], 10.0, runner=spy) == []
    assert calls == []  # no subprocess for nothing to permute


async def test_output_is_capped():
    async def flood(_bin, _args, timeout=None, stdin=None):
        return [f"h{i}.acme.com" for i in range(MAX_PERMUTATIONS + 500)]

    out = await permute(["acme.com"], 10.0, runner=flood, limit=50)
    assert len(out) == 50


async def test_malformed_names_are_dropped():
    async def messy(_bin, _args, timeout=None, stdin=None):
        return ["good.acme.com", "no-dot", "has space.acme.com", "  ", "GOOD2.ACME.COM"]

    out = await permute(["acme.com"], 10.0, runner=messy)
    assert out == ["good.acme.com", "good2.acme.com"]
