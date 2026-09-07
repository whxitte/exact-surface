"""Playground workflow runner — executes a user's canvas.

Walks the graph in topological order, feeding each node's outputs into the next along
the wires the user drew. Pipeline nodes reuse :data:`pipelines.dispatch.ROUTES`, so the
canvas cannot drift from what a scheduled scan does — there is exactly one table
mapping a module name to how it runs, and this is the same one.

**How the safety model works here, precisely.** Two separable things guard a scan:

* the **authorization check** — is there a verified, un-revoked program for this
  tenant (§9b)? Enforced by :func:`pipelines.dispatch.run_pipeline`.
* the **scope engine** — may we send *this action* to *this address*? It is what keeps
  a scanner off cloud metadata endpoints, shared CDN edges and every HARD_DENY class,
  and it is what applies the politeness cap.

A normal run keeps both. A **Target node** waives the first and keeps the second: it
substitutes an ephemeral in-memory :class:`~core.scope.ProgramScope` whose verified
apexes are the hostnames the user typed. Nothing is written to the authorizations
collection, so this grants no lasting permission.

That waiver is deliberate and owner-only. ``docs/SECURITY.md`` §2b already states
plainly that a self-hosted operator owns the database and can write a verification
record by hand — "no self-hosted software can prevent that". So this is not a new
capability for the instance owner; it is the same one, made visible, rate-capped and
written to the audit trail instead of happening unlogged in ``mongosh``. It IS a new
capability for an ordinary member, which is why members cannot use the node at all.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from core.errors import AuthorizationRequired
from core.logging import logger
from core.playground import IMPLS, Graph, by_key, validate
from core.ratelimit import PolitenessLimiter
from core.scope import ProgramScope, ScopeEngine
from core.tenant import TenantContext
from pipelines.dispatch import ROUTES, Ctx, run_pipeline

#: A single node's wall-clock ceiling when the user did not set one. Pipelines have
#: their own budgets; this only bounds a utility node that somehow blocks.
DEFAULT_NODE_TIMEOUT = 900.0

#: Cap the hostnames a Target node may inject. A canvas is interactive — someone
#: pasting a 50k-line list is a mistake, and the politeness limiter would be pacing
#: that run for days.
MAX_FREEFORM_HOSTS = 50


class PlaygroundDenied(Exception):
    """The run is refused for a reason the user needs to read, not a bug."""


def parse_hosts(raw: str) -> list[str]:
    """Hostnames out of the Target node's textarea.

    Accepts newline- or comma-separated input and tolerates people pasting URLs, which
    they will. Strips scheme, path, port and userinfo; drops anything left that cannot
    be a hostname. Lowercased and de-duplicated, order preserved.
    """
    out: list[str] = []
    for chunk in str(raw or "").replace(",", "\n").splitlines():
        host = chunk.strip().lower()
        if not host:
            continue
        if "://" in host:
            host = host.split("://", 1)[1]
        host = host.split("/", 1)[0].split("@")[-1].split(":")[0].strip(".")
        # A hostname, not an IP literal and not a wildcard — the scope engine handles
        # addresses, but a Target node that accepts "*" or "0.0.0.0" is an invitation.
        if not host or "*" in host or " " in host or "." not in host:
            continue
        if host not in out:
            out.append(host)
    return out


def _incoming(graph: Graph) -> dict[str, dict[str, tuple[str, str]]]:
    """node -> {input port: (source node, source port)}."""
    wired: dict[str, dict[str, tuple[str, str]]] = {n: {} for n in graph.nodes}
    for src, src_port, dst, dst_port in graph.edges:
        wired[dst][dst_port] = (src, src_port)
    return wired


def freeform_scope(hosts: list[str], program: dict | None = None) -> ProgramScope:
    """An in-memory scope treating *hosts* as verified apexes, for this run only.

    Exclusions from the real program are carried over deliberately: if an operator has
    said "never touch this host", the Playground is not a way around that.
    """
    program = program or {}
    return ProgramScope(
        verified_apexes=tuple(hosts),
        excluded_hosts=frozenset(program.get("excluded_hosts", [])),
        excluded_cidrs=tuple(program.get("excluded_cidrs", [])),
        # Never inherited: dedicated CIDRs are what unlock port scanning and active
        # content discovery, and they are only ever granted after real ASN
        # confirmation. A typed hostname has proven nothing, so it gets HTTP-layer
        # access only — the same treatment any unconfirmed address gets.
        authorized_dedicated_cidrs=(),
        scan_shared_infra=False,
        # Never inherited: the free-form waiver already relaxes the §9b authorization
        # check, and stacking a scope waiver on top would leave nothing at all.
        scope_override=False,
    )


async def run_workflow(
    *,
    mongo: Any,
    engine: ScopeEngine,
    tenant: TenantContext,
    program_id: str,
    graph: Graph,
    is_owner: bool = False,
    hmac_key: bytes | None = None,
    limiter: PolitenessLimiter | None = None,
    on_event: Callable[[dict], None] | None = None,
) -> dict:
    """Execute *graph* and return per-node results.

    Never raises for a node-level failure: one node erroring marks that node failed
    and skips everything downstream of it (which would only receive nothing anyway),
    while independent branches still run. A canvas where one bad node discards an
    hour of other work would be miserable to iterate in.
    """
    specs = by_key()
    order = validate(graph, specs)  # revalidate: the graph may have changed since save
    wired = _incoming(graph)

    freeform_nodes = [n for n, d in graph.nodes.items() if d.get("type") == "source:target"]
    if freeform_nodes and not is_owner:
        raise PlaygroundDenied(
            "The Target node runs scans against hostnames nobody on this instance has "
            "verified, so it is restricted to the instance owner. Add and verify the "
            "domain as a program to scan it as a member."
        )

    outputs: dict[str, dict[str, Any]] = {}
    report: dict[str, dict[str, Any]] = {}
    skipped: set[str] = set()

    def emit(node_id: str, status: str, **extra: Any) -> None:
        entry = {"status": status, **extra}
        report[node_id] = {**report.get(node_id, {}), **entry}
        if on_event is not None:
            on_event({"node": node_id, **entry})

    for node_id in order:
        node = graph.nodes[node_id]
        spec = specs[node["type"]]
        params = dict(node.get("params") or {})

        upstream = wired.get(node_id, {})
        if any(src in skipped for src, _p in upstream.values()):
            skipped.add(node_id)
            emit(node_id, "skipped", note="an upstream node failed")
            continue

        inputs = {port: outputs[src].get(src_port) for port, (src, src_port) in upstream.items()}
        started = time.monotonic()
        emit(node_id, "running", label=spec.label)
        try:
            produced = await _run_node(
                node_id=node_id,
                spec=spec,
                params=params,
                inputs=inputs,
                mongo=mongo,
                engine=engine,
                tenant=tenant,
                program_id=program_id,
                graph=graph,
                wired=wired,
                outputs=outputs,
                hmac_key=hmac_key,
                limiter=limiter,
            )
        except (AuthorizationRequired, PlaygroundDenied) as exc:
            # A refusal is a message for the user, not a stack trace.
            skipped.add(node_id)
            emit(node_id, "failed", error=str(exc), ms=int((time.monotonic() - started) * 1000))
            logger.info("playground: {} refused — {}", spec.label, exc)
            continue
        except Exception as exc:  # noqa: BLE001 - one node never sinks the canvas
            skipped.add(node_id)
            emit(
                node_id,
                "failed",
                error=f"{type(exc).__name__}: {exc}"[:300],
                ms=int((time.monotonic() - started) * 1000),
            )
            logger.warning("playground: {} failed — {}", spec.label, exc)
            continue

        outputs[node_id] = produced
        emit(
            node_id,
            "success",
            ms=int((time.monotonic() - started) * 1000),
            outputs=_preview(produced),
        )

    return {
        "order": order,
        "nodes": report,
        "outputs": outputs,
        "freeform": bool(freeform_nodes),
    }


def _preview(produced: dict[str, Any]) -> dict[str, Any]:
    """Bound what goes into the run record. A crawl can return thousands of URLs and
    the canvas only needs enough to render — the full value stays in ``outputs``."""
    out: dict[str, Any] = {}
    for port, value in produced.items():
        if isinstance(value, list):
            out[port] = {"count": len(value), "sample": value[:20]}
        else:
            out[port] = value
    return out


async def _run_node(
    *,
    node_id: str,
    spec: Any,
    params: dict[str, Any],
    inputs: dict[str, Any],
    mongo: Any,
    engine: ScopeEngine,
    tenant: TenantContext,
    program_id: str,
    graph: Graph,
    wired: dict[str, dict[str, tuple[str, str]]],
    outputs: dict[str, dict[str, Any]],
    hmac_key: bytes | None,
    limiter: PolitenessLimiter | None,
) -> dict[str, Any]:
    """Execute one node and return ``{output port: value}``."""
    if spec.tier == "source":
        hosts = parse_hosts(params.get("hosts", ""))
        if not hosts:
            raise PlaygroundDenied("No usable hostnames — one per line, e.g. example.com")
        if len(hosts) > MAX_FREEFORM_HOSTS:
            raise PlaygroundDenied(
                f"{len(hosts)} hosts is more than the Playground runs at once "
                f"(limit {MAX_FREEFORM_HOSTS}). Use a program for a surface this size."
            )
        return {"hosts": hosts}

    if spec.tier == "output":
        return {"value": inputs.get("value")}

    if spec.tier == "utility":
        fn = IMPLS[spec.impl]
        kwargs = {**inputs, **{k: v for k, v in params.items() if v not in (None, "")}}
        result = fn(**kwargs)
        port = spec.outputs[0].name if spec.outputs else "value"
        return {port: result}

    # -- pipeline tier -------------------------------------------------------
    targets = tuple(inputs.get("targets") or ())
    timeout = float(params.get("timeout") or 0) or None
    freeform_hosts = _freeform_hosts_feeding(node_id, graph, wired, outputs)

    if freeform_hosts:
        return await _run_pipeline_freeform(
            spec=spec,
            hosts=freeform_hosts,
            targets=targets,
            mongo=mongo,
            engine=engine,
            tenant=tenant,
            program_id=program_id,
            timeout=timeout,
            hmac_key=hmac_key,
            limiter=limiter,
        )

    result = await run_pipeline(
        mongo=mongo,
        engine=engine,
        tenant=tenant,
        program_id=program_id,
        pipeline=spec.pipeline,
        timeout=timeout or DEFAULT_NODE_TIMEOUT,
        hmac_key=hmac_key,
        targets=targets,
        limiter=limiter,
    )
    return {"hosts": list(result.get("cascade_targets") or []), "result": result}


def _freeform_hosts_feeding(
    node_id: str,
    graph: Graph,
    wired: dict[str, dict[str, tuple[str, str]]],
    outputs: dict[str, dict[str, Any]],
) -> list[str]:
    """Hosts reaching *node_id* directly from a Target node, if any.

    Only a **direct** wire counts, and that restraint is the point. If the waiver
    followed the data transitively, a host discovered by a properly-scoped scan could
    be piped onward and silently shed the scope it was found under — the override
    would spread across the canvas invisibly. Requiring the wire to be direct keeps
    every scope waiver visible as an edge the user drew themselves.
    """
    hosts: list[str] = []
    for _port, (src, src_port) in wired.get(node_id, {}).items():
        if graph.nodes.get(src, {}).get("type") != "source:target":
            continue
        hosts.extend((outputs.get(src) or {}).get(src_port) or [])
    return list(dict.fromkeys(hosts))


async def _run_pipeline_freeform(
    *,
    spec: Any,
    hosts: list[str],
    targets: tuple[str, ...],
    mongo: Any,
    engine: ScopeEngine,
    tenant: TenantContext,
    program_id: str,
    timeout: float | None,
    hmac_key: bytes | None,
    limiter: PolitenessLimiter | None,
) -> dict[str, Any]:
    """Run one pipeline against typed hostnames, under an ephemeral scope.

    Reuses ``ROUTES`` rather than re-implementing dispatch, so the canvas and a
    scheduled scan execute the identical code for a given module. What differs is
    only the scope handed in — and that it is never persisted.
    """
    from db.programs import ProgramRepo

    program = await ProgramRepo.from_mongo(mongo).get(tenant.tenant_id, program_id)
    if not program:
        raise AuthorizationRequired(f"no program {program_id} for tenant {tenant.tenant_id}")

    route = ROUTES.get(spec.pipeline)
    if route is None:  # pragma: no cover - the wiring test makes this unreachable
        raise PlaygroundDenied(f"{spec.label} has no runner")

    scope = freeform_scope(hosts, program)
    logger.info(
        "playground: {} on {} host(s) under an ephemeral scope (owner override)",
        spec.pipeline,
        len(hosts),
    )
    ctx = Ctx(
        mongo=mongo,
        engine=engine,
        scope=scope,
        tenant=tenant,
        program_id=program_id,
        apex=hosts[0],
        timeout=timeout or DEFAULT_NODE_TIMEOUT,
        hmac_key=hmac_key,
        limiter=limiter,
        targets=set(targets) or set(hosts),
    )
    result = await route(ctx)
    return {"hosts": list(result.get("cascade_targets") or []), "result": result}
