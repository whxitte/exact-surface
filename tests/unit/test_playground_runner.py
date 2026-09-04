"""The Playground workflow runner (pipelines.playground).

Offline: ``run_pipeline`` and the route table are patched, so these exercise the real
graph walk, wiring and refusal logic without a database or a socket.

The safety-shaped tests are the ones that matter here. The Target node deliberately
waives the §9b authorization check (owner-only, per the user's product decision) while
keeping the scope engine, the politeness cap and the exclusion list. That is a narrow,
defensible waiver — and narrow things widen silently unless something holds them still.
"""

from __future__ import annotations

import pytest

from core.playground import Graph
from core.scope import ScopeEngine
from core.tenant import TenantContext
from pipelines import playground as pg

TENANT = TenantContext("t1", "u1")
ENGINE = ScopeEngine.from_data_file()


def _graph(nodes, edges=()):
    return Graph(nodes=dict(nodes), edges=list(edges))


def _patch_program_repo(monkeypatch, program=None):
    """Stand in for the program lookup the freeform path does.

    ``_run_pipeline_freeform`` calls ``ProgramRepo.from_mongo(mongo)`` before anything
    else, so patching ``.get`` alone is not enough — ``from_mongo`` dereferences the
    (here absent) Mongo handle first.
    """

    class _Repo:
        async def get(self, *_a, **_k):
            return program if program is not None else {"apex_domain": "x.com"}

    monkeypatch.setattr("db.programs.ProgramRepo.from_mongo", classmethod(lambda cls, _m: _Repo()))


async def _run(graph, *, is_owner=True, **kw):
    return await pg.run_workflow(
        mongo=None,
        engine=ENGINE,
        tenant=TENANT,
        program_id="p1",
        graph=graph,
        is_owner=is_owner,
        **kw,
    )


# -- host parsing ------------------------------------------------------------
@pytest.mark.parametrize(
    "raw,expected",
    [
        ("example.com", ["example.com"]),
        ("a.com, b.com", ["a.com", "b.com"]),
        ("a.com\nb.com\n", ["a.com", "b.com"]),
        ("https://a.com/path?q=1", ["a.com"]),  # people paste URLs
        ("A.COM", ["a.com"]),
        ("a.com\na.com", ["a.com"]),  # deduped
        ("user@a.com:8443", ["a.com"]),  # userinfo + port stripped
        ("*.a.com", []),  # wildcards refused
        ("localhost", []),  # no dot = not a hostname
        ("", []),
    ],
)
def test_parse_hosts(raw, expected):
    assert pg.parse_hosts(raw) == expected


# -- the freeform waiver -----------------------------------------------------
async def test_target_node_is_refused_for_non_owners():
    """A member must not gain scanning of unverified hosts. This is the whole
    reason the waiver is acceptable for an owner: SECURITY.md §2b already concedes
    the operator can forge a verification record, but a member cannot."""
    g = _graph({"t": {"type": "source:target", "params": {"hosts": "x.com"}}})
    with pytest.raises(pg.PlaygroundDenied, match="instance owner"):
        await _run(g, is_owner=False)


def test_freeform_scope_never_inherits_dedicated_ranges():
    """Dedicated CIDRs unlock port scanning and active content discovery, and are
    only granted after real ASN confirmation. A typed hostname has proven nothing,
    so it must get HTTP-layer access only."""
    scope = pg.freeform_scope(
        ["x.com"],
        {"excluded_hosts": ["secret.x.com"], "excluded_cidrs": ["10.0.0.0/8"]},
    )
    assert scope.verified_apexes == ("x.com",)
    assert scope.authorized_dedicated_cidrs == ()
    assert scope.scan_shared_infra is False


def test_freeform_scope_still_honours_operator_exclusions():
    """ "Never touch this host" must not be escapable via the Playground."""
    scope = pg.freeform_scope(["x.com"], {"excluded_hosts": ["secret.x.com"]})
    assert "secret.x.com" in scope.excluded_hosts


def test_the_waiver_does_not_travel_down_the_canvas(monkeypatch):
    """Only a DIRECT wire from a Target node waives authorization.

    If the waiver followed data transitively, a host found by a properly-scoped scan
    could be piped onward and shed the scope it was discovered under — the override
    would spread invisibly. Every waiver must stay visible as an edge the user drew.
    """
    seen: list[str] = []

    async def fake_route(ctx):
        seen.append("freeform")
        return {"cascade_targets": ["found.x.com"]}

    async def fake_run_pipeline(**kw):
        seen.append(f"authorized:{kw['pipeline']}")
        return {"cascade_targets": []}

    monkeypatch.setitem(pg.ROUTES, "ingest", fake_route)
    monkeypatch.setattr(pg, "run_pipeline", fake_run_pipeline)
    _patch_program_repo(monkeypatch)

    g = _graph(
        {
            "t": {"type": "source:target", "params": {"hosts": "x.com"}},
            "i": {"type": "pipeline:ingest"},
            "p": {"type": "pipeline:probe"},
        },
        [("t", "hosts", "i", "targets"), ("i", "hosts", "p", "targets")],
    )
    import asyncio

    asyncio.run(_run(g))
    # ingest is wired straight to the Target node -> ephemeral scope.
    # probe is one hop further -> the normal authorized path, NOT the waiver.
    assert seen == ["freeform", "authorized:probe"]


async def test_too_many_freeform_hosts_is_refused():
    many = "\n".join(f"h{i}.example.com" for i in range(pg.MAX_FREEFORM_HOSTS + 5))
    g = _graph({"t": {"type": "source:target", "params": {"hosts": many}}})
    out = await _run(g)
    assert out["nodes"]["t"]["status"] == "failed"
    assert "more than the Playground runs at once" in out["nodes"]["t"]["error"]


# -- graph walking -----------------------------------------------------------
async def test_utility_chain_runs_and_passes_values():
    g = _graph(
        {
            "t": {"type": "source:target", "params": {"hosts": "api.x.com\nwww.y.com"}},
            "f": {"type": "util:filter_hosts", "params": {"contains": "x.com"}},
            "o": {"type": "output:view"},
        },
        [("t", "hosts", "f", "hosts"), ("f", "hosts", "o", "value")],
    )
    out = await _run(g)
    assert out["order"] == ["t", "f", "o"]
    assert out["outputs"]["f"]["hosts"] == ["api.x.com"]
    assert out["outputs"]["o"]["value"] == ["api.x.com"]
    assert all(n["status"] == "success" for n in out["nodes"].values())


async def test_a_failing_node_skips_only_its_descendants(monkeypatch):
    """One bad node must not discard the rest of a canvas the user has been
    iterating on — but a node downstream of it would receive nothing, so it is
    skipped with a reason rather than run against empty input."""

    def boom(**_kw):
        raise RuntimeError("kaboom")

    monkeypatch.setitem(pg.IMPLS, "merge_hosts", boom)

    g = _graph(
        {
            "src": {"type": "source:target", "params": {"hosts": "a.com"}},
            "bad": {"type": "util:merge_hosts"},
            "after": {"type": "output:view"},
            "independent": {
                "type": "util:typosquat_candidates",
                "params": {"domain": "example.com", "limit": 5},
            },
        },
        [("src", "hosts", "bad", "a"), ("bad", "hosts", "after", "value")],
    )
    out = await _run(g)

    assert out["nodes"]["bad"]["status"] == "failed"
    assert out["nodes"]["after"]["status"] == "skipped"
    assert out["nodes"]["after"]["note"] == "an upstream node failed"
    # the unrelated branch is untouched — that is the point
    assert out["nodes"]["independent"]["status"] == "success"


async def test_independent_branches_both_run():
    g = _graph(
        {
            "a": {"type": "util:typosquat_candidates", "params": {"domain": "a.com", "limit": 3}},
            "b": {"type": "util:typosquat_candidates", "params": {"domain": "b.com", "limit": 3}},
        }
    )
    out = await _run(g)
    assert out["nodes"]["a"]["status"] == "success"
    assert out["nodes"]["b"]["status"] == "success"


async def test_node_failure_is_reported_not_raised(monkeypatch):
    def boom(**kw):
        raise RuntimeError("kaboom")

    monkeypatch.setitem(pg.IMPLS, "typosquat_candidates", boom)
    g = _graph({"a": {"type": "util:typosquat_candidates", "params": {"domain": "a.com"}}})
    out = await _run(g)
    assert out["nodes"]["a"]["status"] == "failed"
    assert "kaboom" in out["nodes"]["a"]["error"]


async def test_progress_events_are_emitted_for_live_logs():
    events: list[dict] = []
    g = _graph({"a": {"type": "util:typosquat_candidates", "params": {"domain": "a.com"}}})
    await _run(g, on_event=events.append)
    assert [e["status"] for e in events] == ["running", "success"]
    assert all(e["node"] == "a" for e in events)


async def test_large_outputs_are_summarised_in_the_report():
    """A crawl can return thousands of URLs; the run record must stay small while the
    full value is still available to the next node."""
    g = _graph(
        {"a": {"type": "util:typosquat_candidates", "params": {"domain": "a.com", "limit": 50}}}
    )
    out = await _run(g)
    preview = out["nodes"]["a"]["outputs"]["hosts"]
    assert preview["count"] > 20
    assert len(preview["sample"]) == 20
    assert len(out["outputs"]["a"]["hosts"]) == preview["count"]
