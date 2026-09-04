"""The Playground node catalogue and graph validator (core.playground).

Pure: no DB, no network, no execution. These pin the two properties that make the
canvas safe to expose. First, the pipeline tier is *derived* from the module registry,
so a new module cannot ship without appearing on the canvas — the same drift that gave
us "unknown pipeline" in dispatch and missing labels in the Activity stepper. Second,
the utility tier is a closed allow-list: the only functions reachable from a user's
saved workflow are the ones named in IMPLS, because a graph is user input and
``getattr`` on user input is how a canvas becomes a remote shell.
"""

from __future__ import annotations

import inspect

import pytest

from core import modules as registry
from core.playground import (
    IMPLS,
    Graph,
    GraphError,
    by_key,
    catalogue,
    validate,
)


# -- catalogue ---------------------------------------------------------------
def test_every_registered_module_is_a_pipeline_node():
    """The canvas must not silently omit a capability the product has."""
    keys = {n.key for n in catalogue() if n.tier == "pipeline"}
    missing = [m.name for m in registry.MODULES if f"pipeline:{m.name}" not in keys]
    assert not missing, f"modules with no Playground node: {missing}"


def test_only_cascade_emitting_pipelines_offer_a_hosts_output():
    """Offering a socket that always passes nothing is worse than offering none.

    A pipeline can only feed a downstream node if it publishes cascade_targets. The
    rest still expose their run summary, just not a hosts wire."""
    specs = by_key()
    emits = {"ingest", "probe", "crawl", "uncover", "cloud_assets", "reverse_dns"}
    for module in registry.MODULES:
        spec = specs[f"pipeline:{module.name}"]
        has_hosts = any(p.name == "hosts" for p in spec.outputs)
        assert has_hosts == (module.name in emits), (
            f"{module.name}: hosts output={has_hosts} but emits cascade_targets="
            f"{module.name in emits}"
        )
        assert any(p.name == "result" for p in spec.outputs), f"{module.name} has no result port"


def test_node_keys_are_unique_and_namespaced():
    keys = [n.key for n in catalogue()]
    assert len(keys) == len(set(keys)), "duplicate node keys would collide in saved workflows"
    assert all(":" in k for k in keys), "keys must be namespaced (tier:name)"


def test_every_utility_node_resolves_to_a_declared_impl():
    """A node the runner cannot execute is a dead item in the sidebar."""
    unresolved = [n.key for n in catalogue() if n.tier == "utility" and n.impl not in IMPLS]
    assert not unresolved, f"utility nodes with no implementation: {unresolved}"


def test_impls_are_a_closed_allow_list_not_introspection():
    """The security property: a saved workflow names an impl by string, and that
    string may only ever select from this dict. If this test is ever "fixed" by
    reaching for getattr/importlib on the node's impl field, the canvas becomes a
    way to call arbitrary functions with user-controlled arguments."""
    source = (
        __import__("pathlib").Path(__import__("core.playground", fromlist=["__file__"]).__file__)
    ).read_text()
    for forbidden in ("getattr(", "importlib.import_module(", "eval(", "exec("):
        assert forbidden not in source, (
            f"core/playground.py uses {forbidden} — utility dispatch must stay a literal dict"
        )


def test_declared_utility_params_match_the_real_signatures():
    """The allow-list is hand-written, so it can drift from the functions it names.

    Every declared param/input must be a real keyword the implementation accepts,
    or the node fails at run time with a TypeError the user cannot act on."""
    specs = [n for n in catalogue() if n.tier == "utility"]
    for spec in specs:
        fn = IMPLS[spec.impl]
        accepted = set(inspect.signature(fn).parameters)
        declared = {p.name for p in spec.params} | {p.name for p in spec.inputs}
        unknown = declared - accepted
        assert not unknown, f"{spec.key} declares {unknown}, which {spec.impl}() does not accept"


# -- graph validation --------------------------------------------------------
def _graph(nodes, edges=()):
    return Graph(nodes=dict(nodes), edges=list(edges))


def test_a_straight_chain_sorts_into_run_order():
    g = _graph(
        {
            "a": {"type": "source:target", "params": {"hosts": "x.com"}},
            "b": {"type": "pipeline:probe"},
            "c": {"type": "output:view"},
        },
        [("a", "hosts", "b", "targets"), ("b", "result", "c", "value")],
    )
    assert validate(g) == ["a", "b", "c"]


def test_unknown_node_type_is_rejected_with_the_node_named():
    g = _graph({"a": {"type": "pipeline:does_not_exist"}})
    with pytest.raises(GraphError) as exc:
        validate(g)
    assert exc.value.node_id == "a"


def test_type_mismatch_is_refused():
    """hosts cannot be wired into a headers socket — catching it here means the
    runner never has to guess what the user meant."""
    g = _graph(
        {
            "a": {"type": "source:target", "params": {"hosts": "x.com"}},
            "b": {"type": "util:analyse_cors"},
        },
        [("a", "hosts", "b", "headers")],
    )
    with pytest.raises(GraphError, match="cannot wire"):
        validate(g)


def test_a_missing_required_input_is_refused():
    g = _graph({"b": {"type": "output:view"}})
    with pytest.raises(GraphError, match="needs Value wired"):
        validate(g)


def test_a_missing_required_param_is_refused():
    g = _graph({"a": {"type": "source:target", "params": {}}})
    with pytest.raises(GraphError, match="needs Hosts"):
        validate(g)


def test_double_wiring_one_input_is_refused():
    g = _graph(
        {
            "a": {"type": "source:target", "params": {"hosts": "x.com"}},
            "b": {"type": "source:target", "params": {"hosts": "y.com"}},
            "m": {"type": "util:merge_hosts"},
        },
        [("a", "hosts", "m", "a"), ("b", "hosts", "m", "a")],
    )
    with pytest.raises(GraphError, match="already wired"):
        validate(g)


def test_a_cycle_is_reported_as_a_loop_not_a_crash():
    g = _graph(
        {
            "p": {"type": "pipeline:probe"},
            "c": {"type": "pipeline:crawl"},
        },
        [("p", "hosts", "c", "targets"), ("c", "hosts", "p", "targets")],
    )
    with pytest.raises(GraphError, match="loops back"):
        validate(g)


def test_disconnected_nodes_still_run():
    """Two independent chains on one canvas is a legitimate workflow, not an error."""
    g = _graph(
        {
            "a": {"type": "source:target", "params": {"hosts": "x.com"}},
            "b": {"type": "util:typosquat_candidates", "params": {"domain": "x.com"}},
        }
    )
    assert sorted(validate(g)) == ["a", "b"]


# -- utility implementations -------------------------------------------------
def test_filter_hosts_both_directions():
    f = IMPLS["filter_hosts"]
    hosts = ["api.x.com", "www.x.com", "dev.y.com"]
    assert f(hosts, contains="x.com") == ["api.x.com", "www.x.com"]
    assert f(hosts, contains="x.com", invert=True) == ["dev.y.com"]
    assert f(hosts) == hosts  # no filter configured = pass through


def test_merge_hosts_dedupes_and_keeps_order():
    assert IMPLS["merge_hosts"](["a", "b"], ["b", "c"]) == ["a", "b", "c"]
    assert IMPLS["merge_hosts"](["a"], None) == ["a"]


def test_pick_field_is_forgiving_about_shape():
    assert IMPLS["pick_field"]({"new": 3}, field="new") == 3
    assert IMPLS["pick_field"]({"new": 3}, field="absent") is None
    assert IMPLS["pick_field"]("not a dict", field="new") is None


def test_analysis_nodes_are_pure_and_return_json_safe_shapes():
    """These must not reach the network — they are the nodes a user can run without
    a target, and their output has to survive JSON serialisation into the canvas."""
    import json

    cors = IMPLS["analyse_cors"]({"Access-Control-Allow-Origin": "*"}, url="https://x.com")
    waf = IMPLS["fingerprint_waf"]({"cf-ray": "abc"}, url="https://x.com")
    json.dumps(cors)
    json.dumps(waf)
    assert "Cloudflare" in waf["products"]


def test_typosquat_node_generates_without_resolving():
    out = IMPLS["typosquat_candidates"](domain="example.com", limit=10)
    assert out and all(isinstance(d, str) for d in out)
    assert "example.com" not in out  # the original is not a lookalike of itself
