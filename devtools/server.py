"""Workbench server — a separate, local-only app for testing modules by hand.

Not part of the product. See devtools/README.md for what it is and why it is a separate
app rather than a page inside ExactSurface: this can call a scanning function directly,
which means it can be pointed at a host nobody has proven ownership of. The product's
core promise is that it cannot. So the two must not share a login.
"""

from __future__ import annotations

import asyncio
import json
import time
import traceback
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse

from devtools import introspect

STATIC = Path(__file__).parent / "static"

#: Bind address. Loopback only, deliberately not configurable — see README.
HOST = "127.0.0.1"
PORT = 8765


def _assert_dev_only() -> None:
    """Refuse to run in production. Not overridable by a flag, because the whole point
    is that no configuration mistake can expose this."""
    from core.config import get_settings

    env = getattr(get_settings(), "env", "dev")
    if str(env).lower().startswith("prod"):
        raise SystemExit(
            "devtools refuses to start with EXACTSURFACE_ENV=prod.\n"
            "This is an internal test bench that can call scanning functions directly, "
            "with no scope enforcement. It has no place in production."
        )


# -- run registry ------------------------------------------------------------


@dataclass
class Run:
    """One invocation: its logs, its result, and a handle to cancel it."""

    run_id: str
    label: str
    kind: str  # function | stage
    status: str = "running"  # running | success | failed | cancelled
    started_at: float = field(default_factory=time.time)
    finished_at: float | None = None
    logs: list[str] = field(default_factory=list)
    result: Any = None
    error: str = ""
    task: Any = field(default=None, repr=False)

    def view(self) -> dict:
        # Built by hand rather than with asdict(): asdict deep-copies every field, and
        # the asyncio.Task handle cannot be copied.
        return {
            "run_id": self.run_id,
            "label": self.label,
            "kind": self.kind,
            "status": self.status,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "logs": list(self.logs),
            "result": self.result,
            "error": self.error,
            "duration": round((self.finished_at or time.time()) - self.started_at, 2),
        }


RUNS: dict[str, Run] = {}
#: Keep the last N runs; this is a dev tool, not a datastore.
MAX_RUNS = 50


def _record(run: Run) -> None:
    RUNS[run.run_id] = run
    if len(RUNS) > MAX_RUNS:
        for old in sorted(RUNS.values(), key=lambda r: r.started_at)[: len(RUNS) - MAX_RUNS]:
            RUNS.pop(old.run_id, None)


def _attach_logs(run: Run):
    """Route loguru output into this run's buffer for as long as it is executing."""
    from core.logging import logger

    sink_id = logger.add(
        lambda m: run.logs.append(m.rstrip("\n")),
        level="DEBUG",
        format="{time:HH:mm:ss} | {level: <7} | {name}:{line} - {message}",
    )
    return sink_id


def _detach_logs(sink_id) -> None:
    from core.logging import logger

    try:
        logger.remove(sink_id)
    except ValueError:
        pass


def _jsonable(value: Any) -> Any:
    """Best-effort JSON view of whatever a module returned — these functions return
    dataclasses, tuples of dataclasses, enums, sets. The workbench should show all of
    it rather than failing to serialise."""
    from enum import Enum

    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(v) for v in value]
    if hasattr(value, "__dataclass_fields__"):
        out = {f: _jsonable(getattr(value, f)) for f in value.__dataclass_fields__}
        # dataclass @property values are often the interesting part (severity,
        # evidence, vulnerable) — include them, since that is what you came to see.
        for name in dir(type(value)):
            if name.startswith("_"):
                continue
            if isinstance(getattr(type(value), name, None), property):
                try:
                    out[name] = _jsonable(getattr(value, name))
                except Exception:  # noqa: BLE001, S110 - a property that raises is not
                    pass  # worth failing the whole view over
        return out
    if hasattr(value, "model_dump"):
        try:
            return _jsonable(value.model_dump(mode="json"))
        except Exception:  # noqa: BLE001, S110 - fall through to str() below
            pass
    return str(value)


def _coerce(raw: Any, kind: str) -> Any:
    """Turn a form value into the type the signature wants."""
    if raw is None or raw == "":
        return None
    if kind == "bool":
        if isinstance(raw, bool):
            return raw
        return str(raw).strip().lower() in ("1", "true", "yes", "on")
    if kind == "int":
        return int(raw)
    if kind == "float":
        return float(raw)
    if kind in ("list", "dict"):
        if isinstance(raw, (list, dict)):
            return raw
        text = str(raw).strip()
        if text.startswith(("[", "{")):
            return json.loads(text)
        # A bare comma/newline separated list is what you actually type by hand.
        return [p.strip() for p in text.replace("\n", ",").split(",") if p.strip()]
    if kind == "any":
        text = str(raw).strip()
        if text.startswith(("[", "{")):
            try:
                return json.loads(text)
            except ValueError:
                return raw
        return raw
    return raw


# -- app ---------------------------------------------------------------------

app = FastAPI(title="ExactSurface Workbench", docs_url="/docs")


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(STATIC / "index.html")


@app.get("/api/callables")
async def list_callables() -> dict:
    items = [asdict(c) | {"group": c.group} for c in introspect.discover()]
    return {"count": len(items), "items": items}


@app.get("/api/stages")
async def list_stages() -> dict:
    """Pipeline stages, from the same registry the product uses."""
    from core import modules as registry

    return {
        "items": [
            {
                "name": m.name,
                "label": m.label,
                "summary": m.summary,
                "requires": list(m.requires),
                "opt_in": not m.default_enabled,
            }
            for m in registry.MODULES
        ]
    }


@app.get("/api/programs")
async def list_programs() -> dict:
    """Programs available to run a stage against, read straight from Mongo."""
    try:
        from db.mongo import get_mongo
        from db.programs import ProgramRepo

        rows = await ProgramRepo.from_mongo(get_mongo()).list_all()
    except Exception as exc:  # noqa: BLE001 - the function bench works without a DB
        return {"items": [], "error": f"{type(exc).__name__}: {exc}"}
    return {
        "items": [
            {
                "program_id": r.get("program_id"),
                "tenant_id": r.get("tenant_id"),
                "apex_domain": r.get("apex_domain"),
                "verified": bool(r.get("verified")),
            }
            for r in rows
        ]
    }


@app.post("/api/call")
async def call_function(body: dict) -> dict:
    """Invoke one module function with the supplied arguments."""
    qualname = str(body.get("qualname") or "")
    fn = introspect.resolve(qualname)
    if fn is None:
        raise HTTPException(400, f"unknown or non-callable function: {qualname!r}")

    described = next((c for c in introspect.discover() if c.qualname == qualname), None)
    kinds = {p.name: p.kind for p in (described.params if described else [])}
    supplied = body.get("args") or {}
    kwargs = {}
    for name, raw in supplied.items():
        coerced = _coerce(raw, kinds.get(name, "any"))
        if coerced is not None:
            kwargs[name] = coerced

    run = Run(run_id=uuid.uuid4().hex[:12], label=qualname, kind="function")
    _record(run)
    sink = _attach_logs(run)

    async def execute() -> None:
        try:
            result = fn(**kwargs)
            if asyncio.iscoroutine(result):
                result = await result
            run.result = _jsonable(result)
            run.status = "success"
        except asyncio.CancelledError:
            run.status = "cancelled"
            run.error = "stopped from the workbench"
            raise
        except Exception as exc:  # noqa: BLE001 - showing the traceback IS the feature
            run.status = "failed"
            run.error = f"{type(exc).__name__}: {exc}\n\n{traceback.format_exc()}"
        finally:
            run.finished_at = time.time()
            _detach_logs(sink)

    run.task = asyncio.ensure_future(execute())
    return {"run_id": run.run_id}


@app.post("/api/stage")
async def run_stage(body: dict) -> dict:
    """Run a full pipeline stage against a real program, via the product's dispatcher."""
    name = str(body.get("module") or "")
    program_id = str(body.get("program_id") or "")
    tenant_id = str(body.get("tenant_id") or "")
    if not (name and program_id and tenant_id):
        raise HTTPException(400, "module, program_id and tenant_id are all required")

    run = Run(run_id=uuid.uuid4().hex[:12], label=f"{name} @ {program_id}", kind="stage")
    _record(run)
    sink = _attach_logs(run)

    async def execute() -> None:
        try:
            from core.scope import default_engine
            from core.tenant import TenantContext
            from db.mongo import get_mongo
            from pipelines.dispatch import run_pipeline

            result = await run_pipeline(
                mongo=get_mongo(),
                engine=default_engine(),
                tenant=TenantContext(tenant_id),
                program_id=program_id,
                pipeline=name,
                timeout=float(body.get("timeout") or 300),
            )
            run.result = _jsonable(result)
            run.status = "success"
        except asyncio.CancelledError:
            run.status = "cancelled"
            run.error = "stopped from the workbench"
            raise
        except Exception as exc:  # noqa: BLE001
            run.status = "failed"
            run.error = f"{type(exc).__name__}: {exc}\n\n{traceback.format_exc()}"
        finally:
            run.finished_at = time.time()
            _detach_logs(sink)

    run.task = asyncio.ensure_future(execute())
    return {"run_id": run.run_id}


@app.get("/api/runs")
async def list_runs() -> dict:
    rows = sorted(RUNS.values(), key=lambda r: r.started_at, reverse=True)
    return {"items": [{**r.view(), "logs": r.logs[-3:]} for r in rows]}


@app.get("/api/runs/{run_id}")
async def get_run(run_id: str) -> JSONResponse:
    run = RUNS.get(run_id)
    if not run:
        raise HTTPException(404, "no such run")
    return JSONResponse(run.view())


@app.post("/api/runs/{run_id}/stop")
async def stop_run(run_id: str) -> dict:
    """Cancel a run. The task is cancelled cooperatively, and modules.exec kills any
    subprocess it had started — the same path the product's Stop button uses."""
    run = RUNS.get(run_id)
    if not run:
        raise HTTPException(404, "no such run")
    if run.task and not run.task.done():
        run.task.cancel()
        return {"stopped": True, "run_id": run_id}
    return {"stopped": False, "run_id": run_id, "detail": "already finished"}


def main() -> None:  # pragma: no cover - entry point
    import uvicorn

    _assert_dev_only()
    print(f"\n  ExactSurface Workbench — internal only\n  http://{HOST}:{PORT}\n")
    uvicorn.run(app, host=HOST, port=PORT, log_level="warning")
