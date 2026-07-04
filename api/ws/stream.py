"""Websocket live finding stream.

Authenticates via a ``token`` query param (JWT), sends a snapshot of the tenant's
currently-new findings on connect, then holds the socket open for keepalive.
Phase F upgrades this to push live updates via Redis pub/sub; for now the snapshot
proves the auth + tenant-scoped delivery path.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect

from api.auth import InvalidToken, decode_token
from api.deps import get_mongo_dep
from db.findings import FindingRepo

router = APIRouter()


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
