"""Websocket live streams.

``/ws/findings`` — snapshot of the tenant's currently-new findings on connect.
``/ws/activity`` — snapshot of recent scan-runs, then live ScanRun updates pushed
via the Redis activity bus (falls back to keepalive if no bus is configured; the
frontend keeps polling regardless). Both authenticate via a ``token`` query param.
"""

from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect

from api.auth import InvalidToken, decode_token
from api.deps import clean_doc, get_mongo_dep
from core.activity_bus import get_bus
from db.audit import ScanRunRepo
from db.findings import FindingRepo

router = APIRouter()


def _sort_runs(runs: list[dict]) -> list[dict]:
    runs.sort(key=lambda r: str(r.get("started_at") or r.get("created_at") or ""), reverse=True)
    return runs


@router.websocket("/ws/findings")
async def findings_stream(
    websocket: WebSocket, token: str, mongo: Any = Depends(get_mongo_dep)
) -> None:
    try:
        payload = decode_token(token)
    except InvalidToken:
        await websocket.close(code=4401)
        return

    await websocket.accept()
    tenant_id = payload["tenant_id"]
    docs = await FindingRepo.from_mongo(mongo).list(tenant_id, is_new=True, limit=100)
    await websocket.send_json(
        {
            "type": "snapshot",
            "new_findings": [
                {
                    "name": d.get("name"),
                    "severity": d.get("severity"),
                    "location": d.get("location"),
                }
                for d in docs
            ],
        }
    )
    try:
        while True:
            await websocket.receive_text()  # keepalive
    except WebSocketDisconnect:
        return


@router.websocket("/ws/activity")
async def activity_stream(
    websocket: WebSocket, token: str, mongo: Any = Depends(get_mongo_dep)
) -> None:
    try:
        payload = decode_token(token)
    except InvalidToken:
        await websocket.close(code=4401)
        return

    await websocket.accept()
    tenant_id = payload["tenant_id"]

    runs = await ScanRunRepo.from_mongo(mongo).list(tenant_id, limit=200)
    await websocket.send_json(
        {"type": "snapshot", "runs": [clean_doc(r) for r in _sort_runs(runs)[:60]]}
    )

    bus = get_bus()
    if bus is None or not hasattr(bus, "listen"):
        # No live transport — hold open; the frontend's poll keeps it current.
        try:
            while True:
                await websocket.receive_text()
        except WebSocketDisconnect:
            return
        return

    # Forward published run updates until the client disconnects. The forwarder and
    # the disconnect-watcher race; whichever ends first cancels the other.
    async def _forward() -> None:
        async for run in bus.listen(tenant_id):
            await websocket.send_json({"type": "run", "run": run})

    forwarder = asyncio.create_task(_forward())
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        forwarder.cancel()
