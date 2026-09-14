"""`exactsurface` — the product from a terminal, and from CI.

Every command is one or two API calls through the same client the MCP server uses,
under the same scoped key, so what a person can do here is exactly what an agent
could do with the same key — nothing more, and enforced by the API, not by this file.

Conventions:

* A program may be named by id (``prog_…``) or by apex domain (``acme.com``).
* ``--json`` on any command prints the API's response verbatim for scripting; without
  it you get a table. Errors always go to stderr.
* Exit codes are stable and documented (``exactsurface --help``): 0 ok, 1 error,
  2 usage, 3 refused, 4 not found, 5 findings at or above ``--fail-on``, 6 unreachable.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
import tomllib
from collections.abc import Callable, Coroutine
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.table import Table

from exactsurface_client import __version__
from exactsurface_client.api_client import ExactSurfaceClient, ExactSurfaceError

EXIT_OK, EXIT_ERROR, EXIT_REFUSED, EXIT_NOT_FOUND, EXIT_FAIL_ON, EXIT_UNREACHABLE = 0, 1, 3, 4, 5, 6
SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

app = typer.Typer(
    name="exactsurface",
    help=(
        "ExactSurface from the terminal. Reads and scans through a scoped API key.\n\n"
        "Configure with EXACTSURFACE_URL and EXACTSURFACE_API_KEY, flags, or "
        "~/.config/exactsurface/config.toml.\n\n"
        "Exit codes: 0 ok · 1 error · 2 usage · 3 refused (scope or human-only) · "
        "4 not found · 5 findings at/above --fail-on · 6 instance unreachable."
    ),
    no_args_is_help=True,
    add_completion=True,
    rich_markup_mode="rich",
)
programs_app = typer.Typer(help="Programs (root domains).", no_args_is_help=True)
scan_app = typer.Typer(help="Start, watch and stop scans.", no_args_is_help=True)
playground_app = typer.Typer(help="Validate and run Playground graphs.", no_args_is_help=True)
app.add_typer(programs_app, name="programs")
app.add_typer(scan_app, name="scan")
app.add_typer(playground_app, name="playground")

out = Console()
err = Console(stderr=True)


# --------------------------------------------------------------------------- #
# Configuration and the client
# --------------------------------------------------------------------------- #
def _config_file() -> Path:
    override = os.environ.get("EXACTSURFACE_CONFIG")
    if override:
        return Path(override)
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "exactsurface" / "config.toml"


def _load_config() -> dict[str, Any]:
    path = _config_file()
    if not path.exists():
        return {}
    try:
        data = tomllib.loads(path.read_text())
    except (OSError, tomllib.TOMLDecodeError) as exc:
        err.print(f"[yellow]ignoring {path}: {exc}[/yellow]")
        return {}
    return data.get("default", data) if isinstance(data, dict) else {}


class Ctx:
    def __init__(self, url: str | None, api_key: str | None, insecure: bool, as_json: bool):
        cfg = _load_config()
        self.url = url or os.environ.get("EXACTSURFACE_URL") or cfg.get("url")
        self.api_key = api_key or os.environ.get("EXACTSURFACE_API_KEY") or cfg.get("api_key")
        self.insecure = insecure or bool(cfg.get("insecure", False))
        self.as_json = as_json
        self._client: ExactSurfaceClient | None = None

    def client(self) -> ExactSurfaceClient:
        if self._client is None:
            self._client = ExactSurfaceClient(self.url, self.api_key, verify_tls=not self.insecure)
        return self._client


_injected_client: ExactSurfaceClient | None = None


def set_client(c: ExactSurfaceClient | None) -> None:
    """Inject a client (tests)."""
    global _injected_client
    _injected_client = c


def _version_callback(value: bool) -> None:
    # An option callback, not a check in the group callback: Click resolves the
    # subcommand before running the group callback, so `exactsurface --version` alone
    # would fail with "Missing command" before the check was reached.
    if value:
        out.print(f"exactsurface-client {__version__}")
        raise typer.Exit(EXIT_OK)


@app.callback()
def _root(
    ctx: typer.Context,
    url: str | None = typer.Option(None, "--url", help="Instance URL (or EXACTSURFACE_URL)."),
    api_key: str | None = typer.Option(
        None, "--api-key", help="API key (or EXACTSURFACE_API_KEY)."
    ),
    insecure: bool = typer.Option(
        False, "--insecure", help="Skip TLS verification (self-signed local instance)."
    ),
    as_json: bool = typer.Option(False, "--json", help="Print the raw API response as JSON."),
    version: bool = typer.Option(
        False,
        "--version",
        help="Print the version and exit.",
        callback=_version_callback,
        is_eager=True,
    ),
) -> None:
    ctx.obj = Ctx(url, api_key, insecure, as_json)


def _run(ctx: typer.Context, fn: Callable[[ExactSurfaceClient], Coroutine[Any, Any, Any]]) -> Any:
    """Run one command's coroutine against the client, mapping errors to exit codes."""
    c: Ctx = ctx.obj
    try:
        client = _injected_client or c.client()
    except ExactSurfaceError as exc:
        err.print(f"[red]{exc}[/red]")
        raise typer.Exit(EXIT_ERROR) from None
    try:
        return asyncio.run(fn(client))
    except ExactSurfaceError as exc:
        msg = str(exc)
        err.print(f"[red]{msg}[/red]")
        if msg.startswith("refused"):
            raise typer.Exit(EXIT_REFUSED) from None
        if msg.startswith("not found"):
            raise typer.Exit(EXIT_NOT_FOUND) from None
        if msg.startswith("could not reach") or msg.startswith("ExactSurface did not answer"):
            raise typer.Exit(EXIT_UNREACHABLE) from None
        raise typer.Exit(EXIT_ERROR) from None


def _emit(ctx: typer.Context, data: Any, render: Callable[[Any], None]) -> None:
    if ctx.obj.as_json:
        out.print_json(json.dumps(data, default=str))
    else:
        render(data)


async def _resolve_program(client: ExactSurfaceClient, ref: str) -> str:
    """Accept a program id or an apex domain."""
    if ref.startswith("prog_"):
        return ref
    for p in await client.get("/programs"):
        if p.get("apex_domain", "").lower() == ref.lower().rstrip("."):
            return p["program_id"]
    raise ExactSurfaceError(f"not found: no program for '{ref}' (try `exactsurface programs list`)")


def _table(
    title: str, columns: list[str], rows: list[list[Any]], *, caption: str | None = None
) -> None:
    t = Table(title=title, caption=caption, show_lines=False, expand=False)
    for col in columns:
        t.add_column(col, overflow="fold")
    for r in rows:
        t.add_row(*[("" if v is None else str(v)) for v in r])
    out.print(t)


def _sev(s: str | None) -> str:
    colour = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "cyan",
        "info": "dim",
    }
    s = (s or "").lower()
    return f"[{colour.get(s, '')}]{s}[/]" if s else ""


def _when(v: Any) -> str:
    return str(v)[:19].replace("T", " ") if v else ""


# --------------------------------------------------------------------------- #
# Identity and programs
# --------------------------------------------------------------------------- #
@app.command()
def whoami(ctx: typer.Context) -> None:
    """Who this key is and what it may do."""
    me = _run(ctx, lambda c: c.get("/auth/me"))

    def render(d: dict) -> None:
        rows = [
            ["tenant", d.get("tenant_id")],
            ["auth", d.get("auth")],
            ["role", d.get("role")],
            ["key", d.get("key_id") or "— (session)"],
            ["scopes", ", ".join(d.get("scopes") or []) or "— (session: governed by RBAC)"],
            ["permissions", ", ".join(d.get("permissions") or [])],
        ]
        _table("whoami", ["", ""], rows)

    _emit(ctx, me, render)


@app.command()
def config(ctx: typer.Context) -> None:
    """Show where the URL and key are coming from."""
    c: Ctx = ctx.obj
    cfg = _load_config()

    def src(env: str, key: str) -> str:
        return "env" if os.environ.get(env) else ("config" if cfg.get(key) else "—")

    masked = ("…" + c.api_key[-6:]) if c.api_key else "(unset)"
    rows = [
        ["url", c.url or "(unset)", src("EXACTSURFACE_URL", "url")],
        ["api_key", masked, src("EXACTSURFACE_API_KEY", "api_key")],
        ["config file", str(_config_file()), "exists" if _config_file().exists() else "absent"],
    ]
    _table("configuration", ["setting", "value", "source"], rows)


@programs_app.command("list")
def programs_list(ctx: typer.Context) -> None:
    """Every program this key can see."""
    rows = _run(ctx, lambda c: c.get("/programs"))
    _emit(
        ctx,
        rows,
        lambda ps: _table(
            f"{len(ps)} programs",
            ["program_id", "apex", "verified", "enabled", "override"],
            [
                [
                    p["program_id"],
                    p["apex_domain"],
                    "✓" if p.get("verified") else "–",
                    "✓" if p.get("enabled", True) else "paused",
                    "ON" if p.get("scope_override") else "",
                ]
                for p in ps
            ],
        ),
    )


@programs_app.command("get")
def programs_get(
    ctx: typer.Context, program: str = typer.Argument(..., help="Program id or apex domain")
) -> None:
    """One program's settings."""

    async def go(c: ExactSurfaceClient) -> dict:
        return await c.get(f"/programs/{await _resolve_program(c, program)}")

    d = _run(ctx, go)
    _emit(
        ctx,
        d,
        lambda d: _table(
            d.get("apex_domain", ""),
            ["field", "value"],
            [[k, v] for k, v in d.items() if k != "enabled_modules"],
        ),
    )


@app.command()
def surface(
    ctx: typer.Context, program: str = typer.Argument(..., help="Program id or apex domain")
) -> None:
    """Attack-surface summary: counts by category and the change since last scan."""

    async def go(c: ExactSurfaceClient) -> dict:
        return await c.get(f"/programs/{await _resolve_program(c, program)}/attack-surface")

    d = _run(ctx, go)

    def render(d: dict) -> None:
        cur, chg = d.get("current") or {}, d.get("change") or {}
        rows = []
        for cat in ("assets", "endpoints", "ports", "findings", "secrets", "leaks"):
            cc, ch = cur.get(cat) or {}, chg.get(cat) or {}
            rows.append(
                [cat, cc.get("total", 0), f"+{ch.get('opened', 0)}", f"-{ch.get('resolved', 0)}"]
            )
        _table(
            f"{cur.get('total', 0)} exposed items · net {chg.get('net', 0):+d} since last scan",
            ["category", "total", "opened", "resolved"],
            rows,
            caption=f"latest scan {_when(d.get('latest_scan_at'))}",
        )

    _emit(ctx, d, render)


# --------------------------------------------------------------------------- #
# Data readers
# --------------------------------------------------------------------------- #
def _reader(path: str, title: str, columns: list[str], row: Callable[[dict], list[Any]]):
    def cmd(
        ctx: typer.Context,
        program: str = typer.Argument(..., help="Program id or apex domain"),
        limit: int = typer.Option(100, "--limit", "-n", min=1, max=1000),
    ) -> None:
        async def go(c: ExactSurfaceClient) -> list:
            return await c.get(f"/programs/{await _resolve_program(c, program)}/{path}")

        rows = _run(ctx, go) or []
        _emit(
            ctx,
            rows[:limit],
            lambda rs: _table(f"{title} ({len(rs)} of {len(rows)})", columns, [row(r) for r in rs]),
        )

    return cmd


app.command("assets", help="Discovered hosts.")(
    _reader(
        "assets",
        "assets",
        ["hostname", "ips", "class", "alive", "interest", "last seen"],
        lambda a: [
            a.get("hostname"),
            ", ".join(a.get("resolved_ips") or [])[:40],
            a.get("ip_class"),
            "gone" if a.get("gone") else "✓",
            a.get("interest"),
            _when(a.get("last_seen")),
        ],
    )
)
app.command("endpoints", help="Discovered URLs with risk tags.")(
    _reader(
        "endpoints",
        "endpoints",
        ["url", "status", "source", "risk tags"],
        lambda e: [
            e.get("url"),
            e.get("status_code"),
            e.get("source"),
            ", ".join(e.get("risk_tags") or []),
        ],
    )
)
app.command("ports", help="Open ports on confirmed-dedicated hosts.")(
    _reader(
        "ports",
        "ports",
        ["ip", "port", "proto", "service", "product", "version"],
        lambda p: [
            p.get("ip"),
            p.get("port"),
            p.get("protocol"),
            p.get("service"),
            p.get("product"),
            p.get("version"),
        ],
    )
)
app.command("cves", help="NVD/KEV matches against fingerprinted software.")(
    _reader(
        "cves",
        "cves",
        ["cve", "severity", "cvss", "kev", "asset", "summary"],
        lambda c: [
            c.get("cve_id"),
            _sev(c.get("severity")),
            c.get("cvss"),
            "KEV" if c.get("kev") else "",
            c.get("asset"),
            (c.get("summary") or "")[:70],
        ],
    )
)
app.command("secrets", help="Exposed credentials (masked).")(
    _reader(
        "secrets",
        "secrets",
        ["kind", "severity", "masked", "location", "first seen"],
        lambda s: [
            s.get("kind"),
            _sev(s.get("severity")),
            s.get("masked"),
            (s.get("location") or "")[:60],
            _when(s.get("first_seen")),
        ],
    )
)
app.command("changes", help="The attack-surface diff: appeared, changed, gone.")(
    _reader(
        "deltas",
        "changes",
        ["when", "kind", "severity", "target", "summary"],
        lambda d: [
            _when(d.get("created_at")),
            d.get("kind"),
            _sev(d.get("severity")),
            d.get("target"),
            (d.get("summary") or "")[:70],
        ],
    )
)


@app.command()
def findings(
    ctx: typer.Context,
    program: str = typer.Argument(..., help="Program id or apex domain"),
    severity: str | None = typer.Option(
        None, "--severity", "-s", help="critical|high|medium|low|info"
    ),
    state: str | None = typer.Option(
        None, "--state", help="new|triaged|confirmed|resolved|accepted_risk|regressed"
    ),
    limit: int = typer.Option(100, "--limit", "-n", min=1, max=1000),
) -> None:
    """Findings, most severe first."""

    async def go(c: ExactSurfaceClient) -> list:
        pid = await _resolve_program(c, program)
        return await c.get(f"/programs/{pid}/findings", severity=severity, state=state)

    rows = _run(ctx, go) or []
    _emit(
        ctx,
        rows[:limit],
        lambda rs: _table(
            f"findings ({len(rs)} of {len(rows)})",
            ["severity", "state", "name", "module", "location"],
            [
                [
                    _sev(f.get("severity")),
                    f.get("state"),
                    f.get("name"),
                    f.get("module"),
                    (f.get("location") or "")[:60],
                ]
                for f in rs
            ],
        ),
    )


@app.command()
def paths(
    ctx: typer.Context, program: str = typer.Argument(..., help="Program id or apex domain")
) -> None:
    """Attack paths: findings on one host in the order an attacker would use them."""

    async def go(c: ExactSurfaceClient) -> dict:
        return await c.get(f"/programs/{await _resolve_program(c, program)}/attack-paths")

    d = _run(ctx, go)

    def render(d: dict) -> None:
        items = d.get("paths") if isinstance(d, dict) else d
        if not items:
            out.print("no attack paths (a path needs findings from two or more phases on one host)")
            return
        for p in items:
            out.print(
                f"[bold]{p.get('host')}[/bold]  {_sev(p.get('severity'))}  risk {p.get('risk', '')}"
            )
            for step in p.get("steps") or []:
                out.print(
                    f"   {str(step.get('phase', '')).upper():<12} {step.get('title', '')}  "
                    f"[dim]({step.get('check_id', '')})[/dim]"
                )

    _emit(ctx, d, render)


@app.command()
def audit(
    ctx: typer.Context, limit: int = typer.Option(50, "--limit", "-n", min=1, max=500)
) -> None:
    """Who did what, succeeded or refused. Needs the key's creator to hold settings.manage."""
    d = _run(ctx, lambda c: c.get("/audit", limit=limit))
    _emit(
        ctx,
        d,
        lambda d: _table(
            "audit log",
            ["when", "actor", "action", "program", "status"],
            [
                [
                    _when(e.get("ts")),
                    (f"key {e['key_id']}" if e.get("key_id") else e.get("actor_id")),
                    e.get("action"),
                    e.get("program_id") or "",
                    e.get("status"),
                ]
                for e in d.get("events", [])
            ],
        ),
    )


# --------------------------------------------------------------------------- #
# Scans
# --------------------------------------------------------------------------- #
TERMINAL = {"success", "failed", "cancelled", "skipped"}


async def _wait_for_run(
    c: ExactSurfaceClient, pid: str, scan_id: str, timeout: float, quiet: bool
) -> dict:
    deadline = time.monotonic() + timeout
    last = ""
    while time.monotonic() < deadline:
        runs = await c.get(f"/programs/{pid}/scan-runs")
        run = next((r for r in runs if r.get("scan_id") == scan_id), None)
        status = (run or {}).get("status", "queued")
        stage = ""
        if run and isinstance(run.get("stages"), list):
            running = [s for s in run["stages"] if s.get("status") == "running"]
            stage = f" · {running[0].get('name')}" if running else ""
        line = f"{status}{stage}"
        if line != last and not quiet:
            err.print(f"[dim]{_when(time.strftime('%Y-%m-%dT%H:%M:%S'))}[/dim] {line}")
            last = line
        if status in TERMINAL:
            return run or {"scan_id": scan_id, "status": status}
        await asyncio.sleep(5)
    raise ExactSurfaceError(
        f"scan {scan_id} still running after {int(timeout)}s (it continues on the server)"
    )


@scan_app.command("run")
def scan_run(
    ctx: typer.Context,
    program: str = typer.Argument(..., help="Program id or apex domain"),
    wait: bool = typer.Option(
        False, "--wait", help="Block until the scan finishes, printing progress to stderr."
    ),
    timeout: float = typer.Option(3600, "--timeout", help="Seconds to wait with --wait."),
    fail_on: str | None = typer.Option(
        None,
        "--fail-on",
        help=(
            "With --wait: exit 5 if NEW findings at or above this severity exist afterwards "
            "(critical|high|medium|low)."
        ),
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
) -> None:
    """Start a scan. Needs the scans:run scope. With --wait and --fail-on it is a CI gate."""
    if fail_on and fail_on.lower() not in SEVERITY_ORDER:
        err.print(f"[red]--fail-on must be one of {', '.join(SEVERITY_ORDER)}[/red]")
        raise typer.Exit(2)

    async def go(c: ExactSurfaceClient) -> dict:
        pid = await _resolve_program(c, program)
        started = await c.post(f"/programs/{pid}/scan")
        scan_id = started.get("scan_id")
        result: dict[str, Any] = {"program_id": pid, "started": started}
        if wait and scan_id:
            result["run"] = await _wait_for_run(c, pid, scan_id, timeout, quiet)
            if fail_on:
                threshold = SEVERITY_ORDER.index(fail_on.lower())
                new = await c.get(f"/programs/{pid}/findings", state="new")
                hits = [
                    f
                    for f in new
                    if (f.get("severity") or "info").lower() in SEVERITY_ORDER
                    and SEVERITY_ORDER.index(f["severity"].lower()) >= threshold
                ]
                result["fail_on"] = {
                    "threshold": fail_on.lower(),
                    "matching_new_findings": len(hits),
                    "findings": hits[:50],
                }
        return result

    d = _run(ctx, go)

    def render(d: dict) -> None:
        s = d["started"]
        out.print(
            f"scan [bold]{s.get('scan_id', '')}[/bold] {s.get('status', 'queued')} "
            f"on {d['program_id']}"
        )
        if "run" in d:
            out.print(f"finished: [bold]{d['run'].get('status')}[/bold]")
        if "fail_on" in d:
            fo = d["fail_on"]
            if fo["matching_new_findings"]:
                _table(
                    f"{fo['matching_new_findings']} NEW findings at or above {fo['threshold']}",
                    ["severity", "name", "location"],
                    [
                        [_sev(f.get("severity")), f.get("name"), (f.get("location") or "")[:60]]
                        for f in fo["findings"]
                    ],
                )
            else:
                out.print(f"[green]no new findings at or above {fo['threshold']}[/green]")

    _emit(ctx, d, render)
    if d.get("fail_on", {}).get("matching_new_findings"):
        raise typer.Exit(EXIT_FAIL_ON)


@scan_app.command("list")
def scan_list(
    ctx: typer.Context,
    program: str = typer.Argument(..., help="Program id or apex domain"),
    limit: int = typer.Option(20, "--limit", "-n"),
) -> None:
    """Recent scan runs."""

    async def go(c: ExactSurfaceClient) -> list:
        return await c.get(f"/programs/{await _resolve_program(c, program)}/scan-runs")

    rows = _run(ctx, go) or []
    _emit(
        ctx,
        rows[:limit],
        lambda rs: _table(
            "scan runs",
            ["scan_id", "pipeline", "status", "started", "finished"],
            [
                [
                    r.get("scan_id"),
                    r.get("pipeline"),
                    r.get("status"),
                    _when(r.get("started_at")),
                    _when(r.get("finished_at")),
                ]
                for r in rs
            ],
        ),
    )


@scan_app.command("logs")
def scan_logs(
    ctx: typer.Context,
    program: str = typer.Argument(...),
    scan_id: str = typer.Argument(...),
    tail: int = typer.Option(200, "--tail", "-n"),
) -> None:
    """The tail of one run's log."""

    async def go(c: ExactSurfaceClient) -> dict:
        return await c.get(
            f"/programs/{await _resolve_program(c, program)}/scan-runs/{scan_id}/logs"
        )

    d = _run(ctx, go)
    lines = (d.get("lines") if isinstance(d, dict) else d) or []
    _emit(
        ctx,
        {"scan_id": scan_id, "lines": lines[-tail:]},
        lambda d: [out.print(ln, markup=False, highlight=False) for ln in d["lines"]],
    )


@scan_app.command("cancel")
def scan_cancel(
    ctx: typer.Context, program: str = typer.Argument(...), scan_id: str = typer.Argument(...)
) -> None:
    """Ask a running scan to stop. Needs the scans:run scope."""

    async def go(c: ExactSurfaceClient) -> Any:
        return await c.post(
            f"/programs/{await _resolve_program(c, program)}/scan-runs/{scan_id}/cancel"
        )

    d = _run(ctx, go)
    _emit(
        ctx,
        d or {"scan_id": scan_id, "cancel_requested": True},
        lambda d: out.print(f"cancel requested for {scan_id}"),
    )


# --------------------------------------------------------------------------- #
# Playground
# --------------------------------------------------------------------------- #
def _load_graph(path: Path) -> dict:
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        err.print(f"[red]could not read graph {path}: {exc}[/red]")
        raise typer.Exit(2) from None
    return data.get("graph", data) if isinstance(data, dict) else data


@playground_app.command("nodes")
def playground_nodes(ctx: typer.Context) -> None:
    """The node catalogue."""
    d = _run(ctx, lambda c: c.get("/playground/nodes"))
    _emit(
        ctx,
        d,
        lambda d: _table(
            f"{len(d.get('nodes', []))} nodes",
            ["key", "tier", "inputs", "outputs"],
            [
                [
                    n["key"],
                    n["tier"],
                    ", ".join(f"{p['name']}:{p['type']}" for p in n["inputs"]),
                    ", ".join(f"{p['name']}:{p['type']}" for p in n["outputs"]),
                ]
                for n in d.get("nodes", [])
            ],
        ),
    )


@playground_app.command("validate")
def playground_validate(
    ctx: typer.Context,
    graph: Path = typer.Argument(..., exists=True, help="A JSON file with {nodes, edges}"),
) -> None:
    """Check a graph without running it."""
    g = _load_graph(graph)
    d = _run(ctx, lambda c: c.post("/playground/validate", {"graph": g}))
    _emit(
        ctx,
        d,
        lambda d: out.print(
            f"[green]ok[/green] · run order: {' → '.join(d['order'])}"
            if d.get("ok")
            else f"[red]{d.get('message')}[/red] (node {d.get('node')})"
        ),
    )
    if not d.get("ok"):
        raise typer.Exit(EXIT_ERROR)


@playground_app.command("run")
def playground_run(
    ctx: typer.Context,
    program: str = typer.Argument(..., help="Program id or apex domain — results are stored there"),
    graph: Path = typer.Argument(..., exists=True),
    wait: bool = typer.Option(False, "--wait"),
    timeout: float = typer.Option(1800, "--timeout"),
) -> None:
    """Run a graph. Needs the playground:run scope."""
    g = _load_graph(graph)

    async def go(c: ExactSurfaceClient) -> dict:
        pid = await _resolve_program(c, program)
        started = await c.post("/playground/run", {"program_id": pid, "graph": g})
        if not wait:
            return started
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            snap = await c.get(f"/playground/runs/{started['run_id']}")
            if snap.get("status") in TERMINAL:
                return snap
            await asyncio.sleep(2)
        raise ExactSurfaceError(f"run {started['run_id']} still running after {int(timeout)}s")

    d = _run(ctx, go)

    def render(d: dict) -> None:
        out.print(f"run [bold]{d.get('run_id')}[/bold] {d.get('status')}")
        for nid, rep in (d.get("nodes") or {}).items():
            out.print(
                f"   {nid:<8} {rep.get('status', ''):<8} "
                f"{rep.get('note') or rep.get('error') or ''}"
            )

    _emit(ctx, d, render)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
