"""Playground node catalogue — what a user can drop on the workflow canvas.

The Playground is a visual, user-editable version of something the product already
does invisibly. :data:`taskqueue.cascade.CASCADE` is a hardcoded graph of
``phase -> downstream phases``; every recon pipeline returns the hostnames it found in
``result["cascade_targets"]``, and :func:`pipelines.dispatch.dispatch_pipeline` accepts
``targets=(...)`` to scope a run to specific hosts. That pair — ``cascade_targets`` out,
``targets`` in — *is* the "plug one module's output into another's input" edge. The
canvas exposes it and lets the user rewire it, rather than inventing a second engine.

Two tiers of node, deliberately built differently:

* **Pipeline nodes** are derived from :mod:`core.modules`, so a new module appears on
  the canvas the moment it is registered — no second list to forget. They do real work
  against a real target and therefore run through ``dispatch_pipeline``, which is where
  authorization, scope tiering and the politeness cap are enforced.
* **Utility nodes** are a hand-written allow-list, NOT introspection. ``devtools`` can
  afford to reflect over every callable under ``modules/`` because it is local-only,
  token-gated and 404s in production. The same trick behind a product API would let a
  user name any importable function and hand it arguments — an RCE-adjacent surface. So
  each utility node is declared explicitly here, and a wiring test asserts the
  declaration still matches the real signature. Sync-safety without arbitrary dispatch.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from typing import Any, Literal

from core import modules as registry

#: What flows along an edge. Kept deliberately small: every type here has to be
#: renderable in the UI and serialisable into a saved workflow.
#:
#: ``any`` is the ONLY wildcard, and exists for genuine sinks like the Output viewer.
#: ``json`` is a real type meaning "a JSON record" — it is not a synonym for "anything",
#: or a host list could be wired into a response-headers socket, which is precisely the
#: mistake the validator exists to catch.
PortType = Literal["hosts", "urls", "records", "text", "json", "any"]

#: Pipelines that publish ``cascade_targets`` — the ones that can feed another node.
#: Derived by asking the pipeline module itself rather than hand-listing, so a pipeline
#: that starts (or stops) emitting targets updates this without anyone remembering to.
_EMITS_HOSTS: frozenset[str] = frozenset(
    {"ingest", "probe", "crawl", "uncover", "cloud_assets", "reverse_dns"}
)


@dataclass(frozen=True)
class NodePort:
    """One socket on a node. ``required`` inputs must be wired before a run starts."""

    name: str
    type: PortType
    label: str
    required: bool = False


@dataclass(frozen=True)
class NodeParam:
    """A value the user types into the node's form (not wired from another node)."""

    name: str
    kind: Literal["str", "int", "bool", "select"]
    label: str
    default: Any = None
    required: bool = False
    help: str = ""
    #: for kind="select"
    choices: tuple[str, ...] = ()


@dataclass(frozen=True)
class NodeSpec:
    """One draggable item in the sidebar."""

    key: str  # stable id used in saved workflows, e.g. "pipeline:ingest"
    tier: Literal["pipeline", "utility", "source", "output"]
    label: str
    summary: str
    group: str  # sidebar section
    inputs: tuple[NodePort, ...] = ()
    outputs: tuple[NodePort, ...] = ()
    params: tuple[NodeParam, ...] = ()
    #: pipeline nodes only — the module name dispatch_pipeline routes on.
    pipeline: str = ""
    #: utility nodes only — resolved at execution time by the runner's own table.
    impl: str = ""
    #: shown as a warning in the node's form.
    caution: str = ""


# --------------------------------------------------------------------------
# tier 1: pipeline nodes, derived from the module registry
# --------------------------------------------------------------------------

_HOSTS_IN = NodePort("targets", "hosts", "Targets", required=False)
_HOSTS_OUT = NodePort("hosts", "hosts", "Discovered hosts")
_RESULT_OUT = NodePort("result", "json", "Run summary")


def _pipeline_nodes() -> list[NodeSpec]:
    """One node per registered module. Ports follow the cascade convention.

    Every pipeline accepts ``targets`` (scope this run to these hosts) and returns a
    stats dict. Only the six that publish ``cascade_targets`` also expose a hosts
    output — wiring anything else into a downstream node would silently pass nothing,
    which is worse than the UI simply not offering the socket.
    """
    out: list[NodeSpec] = []
    for spec in registry.MODULES:
        outputs = [_RESULT_OUT]
        if spec.name in _EMITS_HOSTS:
            outputs.insert(0, _HOSTS_OUT)
        out.append(
            NodeSpec(
                key=f"pipeline:{spec.name}",
                tier="pipeline",
                label=spec.label,
                summary=spec.summary,
                group="Scan modules",
                inputs=(_HOSTS_IN,),
                outputs=tuple(outputs),
                params=(
                    NodeParam(
                        "timeout",
                        "int",
                        "Timeout (seconds)",
                        default=None,
                        help="Leave empty to use this module's configured budget.",
                    ),
                ),
                pipeline=spec.name,
                caution=spec.opt_in_reason,
            )
        )
    return out


# --------------------------------------------------------------------------
# tier 2: utility + source/output nodes, explicitly declared
# --------------------------------------------------------------------------

_UTILITY_NODES: tuple[NodeSpec, ...] = (
    NodeSpec(
        key="source:target",
        tier="source",
        label="Target",
        summary=(
            "Feeds hostnames into the canvas. Scanning a domain you do not control is "
            "illegal in most jurisdictions — you are asserting you are authorised."
        ),
        group="Input",
        outputs=(_HOSTS_OUT,),
        params=(
            NodeParam(
                "hosts",
                "str",
                "Hosts",
                required=True,
                help="One hostname per line, or comma-separated.",
            ),
        ),
        caution="Owner-only. Every request is still rate-capped and SSRF-guarded.",
    ),
    NodeSpec(
        key="output:view",
        tier="output",
        label="Output",
        summary="Renders whatever is wired into it. Wire a run summary here to read it.",
        group="Output",
        inputs=(NodePort("value", "any", "Value", required=True),),
    ),
    NodeSpec(
        key="util:filter_hosts",
        tier="utility",
        label="Filter hosts",
        summary="Keeps only hosts containing (or not containing) a substring.",
        group="Utilities",
        inputs=(NodePort("hosts", "hosts", "Hosts", required=True),),
        outputs=(NodePort("hosts", "hosts", "Filtered"),),
        params=(
            NodeParam("contains", "str", "Contains", default="", help="Substring to match."),
            NodeParam("invert", "bool", "Exclude instead", default=False),
        ),
        impl="filter_hosts",
    ),
    NodeSpec(
        key="util:merge_hosts",
        tier="utility",
        label="Merge hosts",
        summary="Combines two host lists, de-duplicated, order preserved.",
        group="Utilities",
        inputs=(
            NodePort("a", "hosts", "Hosts A", required=True),
            NodePort("b", "hosts", "Hosts B"),
        ),
        outputs=(NodePort("hosts", "hosts", "Merged"),),
        impl="merge_hosts",
    ),
    NodeSpec(
        key="util:pick_field",
        tier="utility",
        label="Pick field",
        summary="Pulls one field out of a run summary — e.g. `new` or `discovered`.",
        group="Utilities",
        inputs=(NodePort("value", "json", "Value", required=True),),
        outputs=(NodePort("value", "json", "Field"),),
        params=(NodeParam("field", "str", "Field name", required=True),),
        impl="pick_field",
    ),
    NodeSpec(
        key="util:analyse_cors",
        tier="utility",
        label="CORS verdict",
        summary=(
            "Decides whether response headers hand data to an arbitrary origin. "
            "Pure analysis — sends nothing."
        ),
        group="Analysis",
        inputs=(NodePort("headers", "json", "Response headers", required=True),),
        outputs=(NodePort("verdict", "json", "Verdict"),),
        params=(NodeParam("url", "str", "URL (for the report)", default=""),),
        impl="analyse_cors",
    ),
    NodeSpec(
        key="util:fingerprint_waf",
        tier="utility",
        label="WAF fingerprint",
        summary="Names the WAF/CDN in front of a host from its response headers.",
        group="Analysis",
        inputs=(NodePort("headers", "json", "Response headers", required=True),),
        outputs=(NodePort("verdict", "json", "Products"),),
        params=(NodeParam("url", "str", "URL (for the report)", default=""),),
        impl="fingerprint_waf",
    ),
    NodeSpec(
        key="util:typosquat_candidates",
        tier="utility",
        label="Lookalike candidates",
        summary="Generates phishing-style lookalike domains for a name. Resolves nothing.",
        group="Analysis",
        inputs=(),
        outputs=(NodePort("hosts", "hosts", "Candidates"),),
        params=(
            NodeParam("domain", "str", "Domain", required=True),
            NodeParam("limit", "int", "Max candidates", default=50),
        ),
        impl="typosquat_candidates",
    ),
)


def catalogue() -> list[NodeSpec]:
    """Every node the sidebar offers, pipeline tier first."""
    return [*_pipeline_nodes(), *_UTILITY_NODES]


def by_key() -> dict[str, NodeSpec]:
    return {n.key: n for n in catalogue()}


def as_json() -> list[dict[str, Any]]:
    """Catalogue in the shape the frontend consumes."""
    return [asdict(n) for n in catalogue()]


# --------------------------------------------------------------------------
# graph validation — pure, so the API and the runner share one definition of "valid"
# --------------------------------------------------------------------------


@dataclass
class GraphError(Exception):
    """Why a submitted workflow cannot run. Carries the offending node for the UI."""

    message: str
    node_id: str = ""

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.message


@dataclass
class Graph:
    """A user's canvas: nodes keyed by id, plus edges between their ports."""

    nodes: dict[str, dict[str, Any]] = field(default_factory=dict)
    #: (from_node, from_port, to_node, to_port)
    edges: list[tuple[str, str, str, str]] = field(default_factory=list)


def validate(graph: Graph, specs: dict[str, NodeSpec] | None = None) -> list[str]:
    """Return a topological run order, or raise :class:`GraphError`.

    Rejects unknown node types, edges to sockets that do not exist, type mismatches,
    unwired required inputs, and cycles. Validation is pure and shared by the API
    (reject early, with a message pointing at the node) and the runner (never execute a
    graph that was mutated between submit and run).
    """
    specs = specs or by_key()

    for node_id, node in graph.nodes.items():
        if node.get("type") not in specs:
            raise GraphError(f"unknown node type {node.get('type')!r}", node_id)

    incoming: dict[tuple[str, str], tuple[str, str]] = {}
    for src, src_port, dst, dst_port in graph.edges:
        for end in (src, dst):
            if end not in graph.nodes:
                raise GraphError(f"edge references unknown node {end!r}", end)
        src_spec = specs[graph.nodes[src]["type"]]
        dst_spec = specs[graph.nodes[dst]["type"]]
        out = next((p for p in src_spec.outputs if p.name == src_port), None)
        inp = next((p for p in dst_spec.inputs if p.name == dst_port), None)
        if out is None:
            raise GraphError(f"{src_spec.label} has no output {src_port!r}", src)
        if inp is None:
            raise GraphError(f"{dst_spec.label} has no input {dst_port!r}", dst)
        if out.type != inp.type and "any" not in (out.type, inp.type):
            raise GraphError(
                f"cannot wire {out.type} into {inp.type} ({src_spec.label} → {dst_spec.label})",
                dst,
            )
        if (dst, dst_port) in incoming:
            raise GraphError(f"{dst_spec.label}'s {inp.label} is already wired", dst)
        incoming[(dst, dst_port)] = (src, src_port)

    for node_id, node in graph.nodes.items():
        spec = specs[node["type"]]
        for port in spec.inputs:
            if port.required and (node_id, port.name) not in incoming:
                raise GraphError(f"{spec.label} needs {port.label} wired", node_id)
        for param in spec.params:
            if param.required and not (node.get("params") or {}).get(param.name):
                raise GraphError(f"{spec.label} needs {param.label}", node_id)

    return _toposort(graph)


def _toposort(graph: Graph) -> list[str]:
    """Kahn's algorithm. A cycle is a user error, not a crash — name a node in it."""
    deps: dict[str, set[str]] = {n: set() for n in graph.nodes}
    for src, _sp, dst, _dp in graph.edges:
        deps[dst].add(src)

    order: list[str] = []
    ready = sorted(n for n, d in deps.items() if not d)
    while ready:
        node = ready.pop(0)
        order.append(node)
        for other, d in deps.items():
            if node in d:
                d.discard(node)
                if not d and other not in order and other not in ready:
                    ready.append(other)
        ready.sort()

    if len(order) != len(graph.nodes):
        stuck = sorted(set(graph.nodes) - set(order))
        raise GraphError(
            "this workflow loops back on itself — a node cannot depend on its own output",
            stuck[0] if stuck else "",
        )
    return order


#: Utility implementations, resolved by ``NodeSpec.impl``. A dict, not getattr on a
#: user-supplied string: the only functions reachable from the API are the ones named
#: here. Kept next to the specs so adding a node means touching both.
def _impls() -> dict[str, Callable[..., Any]]:
    from modules.osint.typosquat import generate as _generate
    from modules.scanning.http_misconfig import analyse_cors as _cors
    from modules.scanning.http_misconfig import fingerprint_waf as _waf

    def filter_hosts(hosts: list[str], *, contains: str = "", invert: bool = False) -> list[str]:
        if not contains:
            return list(hosts)
        hit = [h for h in hosts if contains.lower() in h.lower()]
        return [h for h in hosts if h not in hit] if invert else hit

    def merge_hosts(a: list[str], b: list[str] | None = None) -> list[str]:
        return list(dict.fromkeys([*(a or []), *(b or [])]))

    def pick_field(value: Any, *, field: str) -> Any:
        return value.get(field) if isinstance(value, dict) else None

    def analyse_cors(headers: dict, *, url: str = "") -> dict:
        return asdict(_cors(url, headers or {}))

    def fingerprint_waf(headers: dict, *, url: str = "") -> dict:
        verdict = _waf(url, headers or {})
        return {
            "url": verdict.url,
            "products": list(verdict.products),
            "protected": verdict.protected,
        }

    def typosquat_candidates(*, domain: str, limit: int = 50) -> list[str]:
        return [d for d, _technique in _generate(domain, limit=int(limit))]

    return {
        "filter_hosts": filter_hosts,
        "merge_hosts": merge_hosts,
        "pick_field": pick_field,
        "analyse_cors": analyse_cors,
        "fingerprint_waf": fingerprint_waf,
        "typosquat_candidates": typosquat_candidates,
    }


IMPLS = _impls()
