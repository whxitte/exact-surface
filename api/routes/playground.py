"""Playground routes — the node catalogue, saved canvases, and running one.

Runs execute **inline** rather than through the worker queue. That is a deliberate
difference from a scheduled scan: the Playground is an interactive tool where the user
is watching, iterating and expecting to see output, and round-tripping through arq
would cost that immediacy for no benefit. The trade is that a canvas full of long
pipeline nodes ties up a request — which is why ``run`` is rate-limited and the
per-node timeout is bounded.
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status

from api.deps import Principal, get_mongo_dep, get_principal
from api.rate_limit import limiter
from core.config import get_settings
from core.models import Role
from core.playground import Graph, GraphError, as_json, validate
from core.scope import default_engine
from core.tenant import TenantContext
from db.workflows import WorkflowRepo
from pipelines.playground import PlaygroundDenied, run_workflow

router = APIRouter(prefix="/playground", tags=["playground"])


def _graph_from(payload: dict[str, Any]) -> Graph:
    """Build a :class:`Graph` out of request JSON, tolerating the shape React Flow
    sends (edges as objects) as well as the tuple form the validator uses."""
    nodes = payload.get("nodes") or {}
    if not isinstance(nodes, dict):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "nodes must be an object")
    edges: list[tuple[str, str, str, str]] = []
    for edge in payload.get("edges") or []:
        if isinstance(edge, dict):
            edges.append(
                (
                    str(edge.get("source", "")),
                    str(edge.get("sourceHandle") or edge.get("source_port") or ""),
                    str(edge.get("target", "")),
                    str(edge.get("targetHandle") or edge.get("target_port") or ""),
                )
            )
        elif isinstance(edge, (list, tuple)) and len(edge) == 4:
            edges.append(tuple(str(x) for x in edge))  # type: ignore[arg-type]
        else:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"bad edge: {edge!r}")
    return Graph(nodes=nodes, edges=edges)


async def _is_owner_now(mongo: Any, principal: Principal) -> bool:
    """Owner-ness read from the live user record, not from ``principal.is_owner``.

    ``Principal.role`` carries the JWT's ``role`` claim, so it can be stale for up to a
    token lifetime — demote an owner and their existing token still says "owner".
    ``api.deps._resolve_permissions`` already refuses to trust that claim for exactly
    this reason, re-reading owner-ness from the user document; the Target node waives an
    authorization gate, so it has to be at least as careful. An API-key principal with
    no ``created_by`` falls back to the claim, matching how permissions treat that case.
    """
    from db.users import UserRepo

    if not principal.user_id:
        return principal.is_owner
    user = await UserRepo.from_mongo(mongo).get(principal.tenant_id, principal.user_id)
    if not user:
        return False
    return user.get("role") == Role.OWNER.value


@router.get("/nodes")
async def list_nodes() -> dict:
    """The sidebar catalogue. Derived from the module registry, so it never drifts."""
    return {"nodes": as_json()}


@router.get("/workflows")
async def list_workflows(
    principal: Principal = Depends(get_principal),
    mongo: Any = Depends(get_mongo_dep),
) -> dict:
    docs = await WorkflowRepo.from_mongo(mongo).list(principal.tenant_id)
    for d in docs:
        d.pop("_id", None)
    return {"workflows": docs}


@router.put("/workflows/{workflow_id}")
async def save_workflow(
    workflow_id: str,
    body: dict,
    principal: Principal = Depends(get_principal),
    mongo: Any = Depends(get_mongo_dep),
) -> dict:
    """Save a canvas. Validated on the way in so a broken graph is rejected while the
    user still has it on screen, rather than at run time."""
    graph = _graph_from(body.get("graph") or {})
    try:
        validate(graph)
    except GraphError as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            {"message": str(exc), "node": exc.node_id},
        ) from exc

    doc = await WorkflowRepo.from_mongo(mongo).save(
        tenant_id=principal.tenant_id,
        workflow_id=workflow_id,
        name=str(body.get("name") or "Untitled workflow")[:120],
        graph=body.get("graph") or {},
        program_id=str(body.get("program_id") or ""),
    )
    doc.pop("_id", None)
    return doc


@router.delete("/workflows/{workflow_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_workflow(
    workflow_id: str,
    principal: Principal = Depends(get_principal),
    mongo: Any = Depends(get_mongo_dep),
) -> None:
    await WorkflowRepo.from_mongo(mongo).delete(principal.tenant_id, workflow_id)


@router.post("/validate")
async def validate_graph(body: dict) -> dict:
    """Check a canvas without running it — powers inline errors as the user wires."""
    try:
        order = validate(_graph_from(body.get("graph") or {}))
    except GraphError as exc:
        return {"ok": False, "message": str(exc), "node": exc.node_id}
    return {"ok": True, "order": order}


@router.post("/run")
@limiter.limit("6/minute")
async def run(
    request: Request,
    body: dict,
    principal: Principal = Depends(get_principal),
    mongo: Any = Depends(get_mongo_dep),
) -> dict:
    """Execute a canvas and return per-node results.

    ``program_id`` is required even for a free-form run: results are persisted by the
    pipelines themselves and have to belong somewhere the user can find, review and
    delete them. What a Target node changes is the *scope* a node runs under, never
    where its output lands.
    """
    program_id = str(body.get("program_id") or "").strip()
    if not program_id:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "Pick a program for this run — its findings and assets are stored there.",
        )

    graph = _graph_from(body.get("graph") or {})
    events: list[dict] = []
    try:
        result = await run_workflow(
            mongo=mongo,
            engine=default_engine(),
            tenant=TenantContext(principal.tenant_id, principal.user_id),
            program_id=program_id,
            graph=graph,
            is_owner=await _is_owner_now(mongo, principal),
            hmac_key=get_settings().secret_hash_key_bytes(),
            on_event=events.append,
        )
    except GraphError as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            {"message": str(exc), "node": exc.node_id},
        ) from exc
    except PlaygroundDenied as exc:
        # 403, not 500: this is a policy answer the user needs to read.
        raise HTTPException(status.HTTP_403_FORBIDDEN, str(exc)) from exc

    # `outputs` can hold a full crawl; the report's bounded previews are what the UI
    # renders. Returning both would double a large payload for no gain.
    return {
        "run_id": "pgr_" + uuid.uuid4().hex[:12],
        "order": result["order"],
        "nodes": result["nodes"],
        "freeform": result["freeform"],
        "events": events,
    }
