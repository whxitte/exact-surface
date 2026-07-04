"""Report download endpoint — HTML / HackerOne markdown / executive / PDF."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status

from api.deps import Principal, get_mongo_dep, get_principal, require_program
from core.tenant import TenantContext
from pipelines.report import generate_report

router = APIRouter(prefix="/programs", tags=["reports"])


@router.get("/{program_id}/reports")
async def download_report(
    format: str = Query(default="html"),
    program: dict = Depends(require_program),
    principal: Principal = Depends(get_principal),
    mongo: Any = Depends(get_mongo_dep),
) -> Response:
    try:
        report = await generate_report(
            mongo=mongo,
            tenant=TenantContext(tenant_id=principal.tenant_id, actor_id=principal.user_id),
            program_id=program["program_id"],
            fmt=format,
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    except (ModuleNotFoundError, OSError) as exc:
        # PDF rendering needs WeasyPrint + native libs; degrade cleanly.
        raise HTTPException(
            status.HTTP_501_NOT_IMPLEMENTED,
            "PDF rendering is unavailable (WeasyPrint not installed); "
            "use format=html, hackerone, or executive instead.",
        ) from exc

    return Response(
        content=report.body,
        media_type=report.content_type,
        headers={"Content-Disposition": f'attachment; filename="{report.filename}"'},
    )
