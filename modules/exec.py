"""Subprocess execution for tool wrappers (§3.5, §11).

Every external tool runs through :func:`run_tool`, which guarantees the invariants
the coding standards require: a timeout, a hard kill on timeout, and structured
errors for the missing-binary / timeout / non-zero cases. Wrappers never call
``asyncio.create_subprocess_exec`` directly.

Most of the toolchain (ProjectDiscovery especially) emits newline-delimited JSON;
:func:`run_tool_jsonl` runs a tool and parses that stream, tolerating the odd
non-JSON line (banners, warnings) rather than failing the whole run.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
from collections.abc import Iterator, Sequence
from dataclasses import dataclass

from core.errors import ToolExecutionError, ToolNotFound, ToolTimeout
from core.logging import logger


@dataclass
class ToolRun:
    binary: str
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


async def run_tool(
    binary: str,
    args: Sequence[str],
    *,
    timeout: float,
    stdin: str | None = None,
    check: bool = False,
    env: dict[str, str] | None = None,
) -> ToolRun:
    """Run ``binary args`` with a hard timeout. Kills the process on timeout.

    ``env`` adds/overrides environment variables for the child (merged over the
    parent env) — used to hand a tool a per-tenant API key without leaking it into
    the worker's own environment.

    Raises :class:`ToolNotFound` if the binary is missing, :class:`ToolTimeout` on
    timeout (after killing), and — only when ``check=True`` —
    :class:`ToolExecutionError` on a non-zero exit.
    """
    if shutil.which(binary) is None:
        raise ToolNotFound(binary)

    logger.debug("exec: {} {}", binary, " ".join(args))
    try:
        proc = await asyncio.create_subprocess_exec(
            binary,
            *args,
            stdin=asyncio.subprocess.PIPE if stdin is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={**os.environ, **env} if env else None,
        )
    except FileNotFoundError as exc:  # race: vanished between which() and exec
        raise ToolNotFound(binary) from exc

    payload = stdin.encode() if stdin is not None else None
    try:
        out, err = await asyncio.wait_for(proc.communicate(payload), timeout=timeout)
    except TimeoutError as exc:
        proc.kill()
        await proc.wait()
        logger.warning("tool {} killed after {:.0f}s timeout", binary, timeout)
        raise ToolTimeout(binary, timeout) from exc

    run = ToolRun(
        binary,
        proc.returncode or 0,
        out.decode(errors="replace"),
        err.decode(errors="replace"),
    )
    if check and not run.ok:
        raise ToolExecutionError(f"{binary} exited {run.returncode}: {run.stderr.strip()[:200]}")
    return run


async def stream_tool(
    binary: str,
    args: Sequence[str],
    *,
    timeout: float,
    stdin: str | None = None,
    on_stdout=None,
    on_stderr=None,
) -> tuple[int, list[str], str, bool]:
    """Run a tool, streaming stdout/stderr line-by-line to callbacks as they arrive.

    Unlike :func:`run_tool` (which buffers everything until exit), this surfaces
    output live — essential for a long scanner like nuclei so progress and findings
    show up in the logs in real time. Returns ``(returncode, stdout_lines,
    stderr_text, timed_out)``. On timeout the process is killed but whatever was
    already read is returned — partial results are never lost.
    """
    if shutil.which(binary) is None:
        raise ToolNotFound(binary)

    logger.debug("exec(stream): {} {}", binary, " ".join(args))
    proc = await asyncio.create_subprocess_exec(
        binary,
        *args,
        stdin=asyncio.subprocess.PIPE if stdin is not None else None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout_lines: list[str] = []
    stderr_lines: list[str] = []

    async def _pump(stream, sink, cb) -> None:
        # Read fixed-size chunks and split on newlines ourselves. `async for`/
        # readline() cap a single line at asyncio's StreamReader limit (64 KB) and
        # raise ValueError past it — nuclei JSONL findings that embed a large HTTP
        # response blow through that and would kill the whole scan. Chunked reads
        # have no per-line limit.
        buf = b""
        while True:
            chunk = await stream.read(65536)
            if not chunk:
                break
            buf += chunk
            while b"\n" in buf:
                raw, buf = buf.split(b"\n", 1)
                line = raw.decode(errors="replace")
                sink.append(line)
                if cb is not None:
                    cb(line)
        if buf:  # trailing line with no final newline
            line = buf.decode(errors="replace")
            sink.append(line)
            if cb is not None:
                cb(line)

    async def _feed() -> None:
        if stdin is not None and proc.stdin is not None:
            proc.stdin.write(stdin.encode())
            await proc.stdin.drain()
            proc.stdin.close()

    timed_out = False
    try:
        await asyncio.wait_for(
            asyncio.gather(
                _feed(),
                _pump(proc.stdout, stdout_lines, on_stdout),
                _pump(proc.stderr, stderr_lines, on_stderr),
            ),
            timeout=timeout,
        )
        await proc.wait()
    except TimeoutError:
        timed_out = True
        proc.kill()
        await proc.wait()
        logger.warning("tool {} killed after {:.0f}s (partial output kept)", binary, timeout)
    return proc.returncode or 0, stdout_lines, "\n".join(stderr_lines), timed_out


def iter_jsonl(text: str) -> Iterator[dict]:
    """Yield JSON objects from newline-delimited JSON, skipping blank/non-JSON lines."""
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            yield obj


async def run_tool_jsonl(
    binary: str,
    args: Sequence[str],
    *,
    timeout: float,
    stdin: str | None = None,
) -> list[dict]:
    """Run a JSONL-emitting tool and return the parsed objects.

    A non-zero exit is tolerated (many recon tools exit non-zero when they find
    nothing) as long as stdout parsed; genuine failures surface as empty output,
    which the caller treats as "no results".
    """
    run = await run_tool(binary, args, timeout=timeout, stdin=stdin, check=False)
    return list(iter_jsonl(run.stdout))


async def run_tool_lines(
    binary: str,
    args: Sequence[str],
    *,
    timeout: float,
    stdin: str | None = None,
    env: dict[str, str] | None = None,
) -> list[str]:
    """Run a line-emitting tool (gau, waybackurls) and return stripped non-empty lines."""
    run = await run_tool(binary, args, timeout=timeout, stdin=stdin, check=False, env=env)
    return [ln.strip() for ln in run.stdout.splitlines() if ln.strip()]


async def run_tool_stdout(
    binary: str,
    args: Sequence[str],
    *,
    timeout: float,
    stdin: str | None = None,
) -> str:
    """Run a tool and return its raw stdout (for nmap greppable, ffuf JSON blob, ...)."""
    run = await run_tool(binary, args, timeout=timeout, stdin=stdin, check=False)
    return run.stdout
