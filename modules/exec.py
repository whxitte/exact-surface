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
) -> ToolRun:
    """Run ``binary args`` with a hard timeout. Kills the process on timeout.

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
