"""Workbench server — a separate, local-only app for testing modules by hand.

Not part of the product. See devtools/README.md for what it is and why it is a separate
app rather than a page inside ExactSurface: this can call a scanning function directly,
which means it can be pointed at a host nobody has proven ownership of. The product's
core promise is that it cannot. So the two must not share a login.

Threat model
------------
The workbench adds **no endpoint to ExactSurface**. It imports the Python modules and
talks to Mongo in-process; there is nothing on the product's API for an outsider to
find or guess. The attack surface is this server alone, and it is not the internet —
it is the developer's own machine:

1. **A website the developer visits.** A browser will happily send a cross-origin
   request to ``http://127.0.0.1:8765``. Any page open in another tab could otherwise
   POST to ``/api/call`` and run a scanner from the developer's machine. This is the
   real threat and it is why a loopback bind alone is *not* sufficient.
2. **DNS rebinding.** An attacker points ``evil.com`` at 127.0.0.1, so the browser
   treats their origin as same-origin with us. Defeated by checking ``Host``.
3. **Another process or user on the same machine.** Defeated by the per-run token.

Three controls, all enforced in :func:`_guard` before any route runs:

* a **per-run token** (``secrets.token_urlsafe(32)``, new every start, never written to
  disk) required as a query parameter or header — so the URL is unguessable, and
  knowing the port is not enough;
* a **Host allow-list** — only ``127.0.0.1``/``localhost`` on our port, so a rebound
  DNS name is rejected;
* an **Origin / Sec-Fetch-Site check** — any cross-site browser request is refused
  outright, even if it somehow carried a valid token.

For a product whose entire proposition is finding other people's exposed surface,
shipping a tool that exposes our own would be the worst possible advertisement. Hence
belt, braces, and a documented reason for each.
"""

from __future__ import annotations

import asyncio
import json
import secrets
import time
import traceback
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

from devtools import introspect

STATIC = Path(__file__).parent / "static"

#: Bind address. Loopback only, deliberately not configurable — see README.
HOST = "127.0.0.1"
PORT = 8765

#: Regenerated on every start and never persisted. Restarting invalidates old links,
#: which is the correct default for a tool that should not be left running.
TOKEN: str = secrets.token_urlsafe(32)

#: Header the UI sends. A query parameter is accepted too, for the initial page load
#: and for curl.
TOKEN_HEADER = "x-workbench-token"  # noqa: S105 - a header NAME, not a secret
TOKEN_PARAM = "t"  # noqa: S105 - a query-parameter NAME, not a secret

_ALLOWED_HOSTS = frozenset({
    f"127.0.0.1:{PORT}", f"localhost:{PORT}", f"[::1]:{PORT}",
})
_ALLOWED_ORIGINS = frozenset({
    f"http://127.0.0.1:{PORT}", f"http://localhost:{PORT}", f"http://[::1]:{PORT}",
})


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


def _guard(request: Request) -> None:
    """Reject anything that is not this machine's own browser tab. Raises 404, not 403.

    404 is deliberate: a wrong or absent token should make the whole server look like
    it is not there, rather than confirming to a prober that something exists here and
    only the credential is missing.
    """
    # 1. Host allow-list — defeats DNS rebinding, where a browser is tricked into
    #    treating an attacker's domain as same-origin with loopback.
    host = (request.headers.get("host") or "").lower()
    if host not in _ALLOWED_HOSTS:
        raise HTTPException(404)

    # 2. Cross-site browser requests are refused outright. Sec-Fetch-Site is sent by
    #    every current browser and cannot be forged by page JavaScript; Origin covers
    #    the rest. Neither is present on curl, which is fine — the token still gates it.
    if (request.headers.get("sec-fetch-site") or "same-origin") not in (
        "same-origin", "none",
    ):
        raise HTTPException(404)
    origin = request.headers.get("origin")
    if origin and origin.lower() not in _ALLOWED_ORIGINS:
        raise HTTPException(404)

    # 3. The token itself. Compared in constant time so the check cannot be walked
    #    character by character with timing.
    supplied = request.headers.get(TOKEN_HEADER) or request.query_params.get(TOKEN_PARAM) or ""
    if not secrets.compare_digest(supplied, TOKEN):
        raise HTTPException(404)


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
async def index(request: Request) -> HTMLResponse:
    """The UI. Requires ?t=<token>, so the URL printed at startup is the only way in.

    The token is injected into the page rather than left in the address bar for the
    JS to re-read, so it travels as a header on every subsequent call.
    """
    _guard(request)
    html = (STATIC / "index.html").read_text()
    return HTMLResponse(html.replace("__WORKBENCH_TOKEN__", TOKEN))


@app.get("/api/callables")
async def list_callables(request: Request) -> dict:
    _guard(request)
    items = [asdict(c) | {"group": c.group} for c in introspect.discover()]
    return {"count": len(items), "items": items}


@app.get("/api/stages")
async def list_stages(request: Request) -> dict:
    """Pipeline stages, from the same registry the product uses."""
    _guard(request)
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
async def list_programs(request: Request) -> dict:
    """Programs available to run a stage against, read straight from Mongo."""
    _guard(request)
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
async def call_function(request: Request, body: dict) -> dict:
    """Invoke one module function with the supplied arguments."""
    _guard(request)
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
async def run_stage(request: Request, body: dict) -> dict:
    """Run a full pipeline stage against a real program, via the product's dispatcher."""
    _guard(request)
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
async def list_runs(request: Request) -> dict:
    _guard(request)
    rows = sorted(RUNS.values(), key=lambda r: r.started_at, reverse=True)
    return {"items": [{**r.view(), "logs": r.logs[-3:]} for r in rows]}


@app.get("/api/runs/{run_id}")
async def get_run(request: Request, run_id: str) -> JSONResponse:
    _guard(request)
    run = RUNS.get(run_id)
    if not run:
        raise HTTPException(404, "no such run")
    return JSONResponse(run.view())


@app.post("/api/runs/{run_id}/stop")
async def stop_run(request: Request, run_id: str) -> dict:
    """Cancel a run. The task is cancelled cooperatively, and modules.exec kills any
    subprocess it had started — the same path the product's Stop button uses."""
    _guard(request)
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
    url = f"http://{HOST}:{PORT}/?{TOKEN_PARAM}={TOKEN}"
    print(
        "\n  ExactSurface Workbench — internal only, not part of the product"
        f"\n\n  {url}\n"
        "\n  The token is new on every start and is never written to disk."
        "\n  Without it every path returns 404, including this one.\n",
        flush=True,  # so the URL appears even when stdout is redirected to a log
    )
    uvicorn.run(app, host=HOST, port=PORT, log_level="warning")
