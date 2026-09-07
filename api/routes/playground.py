"""Playground routes — the node catalogue, saved canvases, and running one.

Runs are **enqueued to the worker**, not executed inline. That is not a stylistic
choice, it is forced by where the tools live: the recon toolchain (subfinder, httpx,
nuclei, naabu, feroxbuster...) ships only in the pipeline image, which is what the
worker runs. ``docker/Dockerfile.api`` deliberately carries none of it — the API
serves JSON, and adding ~2GB of Go binaries and wordlists would bloat it and widen its
CVE surface for nothing.

An earlier version of this module ran canvases inline for interactivity. It worked for
utility nodes and failed every pipeline node with ``ToolNotFound: subfinder`` the first
time it met a real scan, because the API container has no scanner. Progress therefore
arrives the same way a scheduled scan's does: written to the run's ScanRun row, which
``save`` also publishes to the activity bus, and polled via ``GET /playground/runs/…``.
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status

from api.deps import Principal, get_mongo_dep, get_principal
from api.rate_limit import limiter
from core.logging import logger
from core.models import Role, ScanRun, ScanStatus
from core.playground import Graph, GraphError, as_json, validate
from db.audit import ScanRunRepo
from db.workflows import WorkflowRepo

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
    """Queue a canvas for execution and return the run id to poll.

    ``program_id`` is required even for a free-form run: results are persisted by the
    pipelines themselves and have to belong somewhere the user can find, review and
    delete them. What a Target node changes is the *scope* a node runs under, never
    where its output lands.

    The graph is validated and the owner check is applied *here*, synchronously, so a
    refusal reaches the user as a 4xx they can read rather than a job that quietly dies
    in a worker log. The runner re-checks both — a queued payload must never be trusted.
    """
    program_id = str(body.get("program_id") or "").strip()
    if not program_id:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "Pick a program for this run — its findings and assets are stored there.",
        )

    graph = _graph_from(body.get("graph") or {})
    try:
        validate(graph)
    except GraphError as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            {"message": str(exc), "node": exc.node_id},
        ) from exc

    is_owner = await _is_owner_now(mongo, principal)
    if any(n.get("type") == "source:target" for n in graph.nodes.values()) and not is_owner:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "The Target node scans hostnames nobody on this instance has verified, so it "
            "is restricted to the instance owner. Add and verify the domain as a program "
            "to scan it as a member.",
        )

    scan_id = uuid.uuid4().hex
    audit = ScanRunRepo.from_mongo(mongo)
    await audit.save(
        ScanRun(
            tenant_id=principal.tenant_id,
            program_id=program_id,
            scan_id=scan_id,
            pipeline="playground",
            status=ScanStatus.QUEUED,
        )
    )

    payload = {
        "nodes": graph.nodes,
        "edges": [list(e) for e in graph.edges],
    }
    enqueued = False
    try:
        from taskqueue.arq_client import create_pool

        pool = await create_pool()
        try:
            await pool.enqueue_job(
                "run_playground_task",
                principal.tenant_id,
                program_id,
                payload,
                scan_id=scan_id,
                is_owner=is_owner,
            )
            enqueued = True
        finally:
            await pool.aclose()
    except Exception as exc:  # noqa: BLE001 - report it, do not 500
        logger.warning("playground enqueue failed: {}", exc)

    if not enqueued:
        await audit.save(
            ScanRun(
                tenant_id=principal.tenant_id,
                program_id=program_id,
                scan_id=scan_id,
                pipeline="playground",
                status=ScanStatus.FAILED,
                error="could not reach the job queue — is the worker running?",
            )
        )
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "Could not reach the job queue. Is the worker running?",
        )

    return {"run_id": scan_id, "status": "queued"}


@router.get("/runs/{run_id}")
async def run_status(
    run_id: str,
    principal: Principal = Depends(get_principal),
    mongo: Any = Depends(get_mongo_dep),
) -> dict:
    """Poll one run. ``nodes`` carries each node's status as the worker reports it."""
    doc = await ScanRunRepo.from_mongo(mongo).get(principal.tenant_id, run_id)
    if not doc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such run")
    return {
        "run_id": run_id,
        "status": doc.get("status"),
        "nodes": (doc.get("stats") or {}).get("nodes") or {},
        "error": doc.get("error"),
        "finished_at": doc.get("finished_at"),
    }
