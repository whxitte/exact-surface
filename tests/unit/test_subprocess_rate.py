"""Every scanner subprocess is rate-capped, and that is verifiable (§3.8b, ADR-0013).

A token bucket cannot govern a subprocess — httpx, katana, nuclei, feroxbuster,
ffuf and naabu send their own packets, so the ceiling has to be a flag handed to
the tool. naabu got one first (ADR-0009); the others defaulted to 150 rps (the PD
tools) or unlimited (feroxbuster/ffuf) and passed no flag at all.

Two kinds of test here: the derivation math, and a source-level guard that each
wrapper actually passes the flag — because, exactly like the dead limiter, "the
tool supports a rate flag" and "we pass it" are different facts and only the second
one keeps the promise.
"""

from __future__ import annotations

from pathlib import Path

from core.metrics import MetricsRegistry
from core.ratelimit import SUBPROCESS_RATE_CEILING, derive_subprocess_rate

ROOT = Path(__file__).resolve().parents[2]


def test_per_target_rate_stays_within_the_cap():
    r = derive_subprocess_rate(10, 10.0, tool="httpx")
    assert r.aggregate == 100  # 10 hosts x 10 pps
    assert r.per_target == 10.0
    assert r.within_cap


def test_a_single_host_gets_exactly_the_cap():
    """The per-host tools (katana, feroxbuster, ffuf) call with host_count=1, so the
    flag they hand over must be the cap itself — not more."""
    r = derive_subprocess_rate(1, 10.0, tool="katana")
    assert r.aggregate == 10
    assert r.per_target == 10.0


def test_zero_hosts_never_divides_by_zero():
    r = derive_subprocess_rate(0, 10.0, tool="nuclei")
    assert r.aggregate >= 1
    assert r.within_cap


def test_the_aggregate_is_clamped_to_the_absolute_ceiling():
    """A huge host list must not hand a tool an unbounded rate — our own egress
    needs a hard stop regardless of per-target math."""
    r = derive_subprocess_rate(10_000, 10.0, tool="httpx")
    assert r.aggregate == SUBPROCESS_RATE_CEILING


def test_it_publishes_a_verifiable_per_tool_metric(monkeypatch):
    """The §15 exit gate is 'verified by metrics', so the derivation must emit, and
    the tool label is what lets an operator see WHICH tool if one slips."""
    reg = MetricsRegistry()
    import core.ratelimit as rl

    monkeypatch.setattr(rl, "REGISTRY", reg)
    derive_subprocess_rate(5, 10.0, tool="feroxbuster")

    out = reg.render()
    assert 'vantari_subprocess_per_target_pps{tool="feroxbuster"} 10.0' in out
    assert 'vantari_subprocess_rate_pps{tool="feroxbuster"} 50.0' in out
    assert "vantari_politeness_rate_limit_pps 10.0" in out


# -- the source-level guard: wrappers must actually pass the flag ------------
#: (wrapper file, the rate flag it must pass). One entry per tool that talks to a
#: customer host. Adding a tool here without its flag is the ADR-0013 regression.
_RATE_FLAGGED = {
    "modules/probing/httpx.py": '"-rl"',
    "modules/crawling/katana.py": '"-rl"',
    "modules/scanning/nuclei.py": '"-rl"',
    "modules/content_discovery/feroxbuster.py": '"--rate-limit"',
    "modules/content_discovery/ffuf.py": '"-rate"',
    "modules/ports/naabu.py": '"-rate"',
}


def test_every_target_facing_wrapper_passes_a_rate_flag():
    for rel, flag in _RATE_FLAGGED.items():
        src = (ROOT / rel).read_text()
        assert flag in src, f"{rel} no longer passes {flag} — its rate cap is gone (§3.8b)"
        assert "rate" in src, f"{rel} has no rate parameter"


def test_the_pipelines_derive_and_pass_the_rate():
    """The wrappers accept a rate; the pipelines must actually derive one. Without
    this, every wrapper falls back to its DEFAULT_RATE and the per-target math that
    scales with host count never runs."""
    for rel in (
        "pipelines/probe.py",
        "pipelines/crawl.py",
        "pipelines/scan.py",
        "pipelines/content_discovery.py",
        "pipelines/port_scan.py",
    ):
        src = (ROOT / rel).read_text()
        assert "derive_subprocess_rate(" in src, f"{rel} does not derive a subprocess rate"
