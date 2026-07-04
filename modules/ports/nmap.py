"""nmap wrapper — service/version identification (module 12).

Runs a rate-capped, non-intrusive ``-sV`` scan and parses the greppable output
(no XML dependency). Only "safe"/default scripts are used — no aggressive NSE.
"""

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable

from modules.exec import run_tool_stdout

Runner = Callable[..., Awaitable[str]]

# Greppable port field: port/state/proto/owner/service/rpc/version/
_PORT_RE = re.compile(r"(\d+)/(\w+)/(\w+)//([^/]*)//([^/]*)/")


async def service_scan(
    ip: str,
    ports: list[int],
    timeout: float,
    *,
    max_rate: int = 10,
    runner: Runner = run_tool_stdout,
) -> list[dict]:
    """Return ``{port, protocol, state, service, version}`` for the given ports on *ip*."""
    if not ports:
        return []
    port_arg = ",".join(str(p) for p in sorted(set(ports)))
    out = await runner(
        "nmap",
        [
            "-sV",
            "-Pn",
            "--version-light",
            "--max-rate",
            str(max_rate),
            "-p",
            port_arg,
            "-oG",
            "-",
            ip,
        ],
        timeout=timeout,
    )
    results: list[dict] = []
    for line in out.splitlines():
        if "Ports:" not in line:
            continue
        for port, state, proto, service, version in _PORT_RE.findall(line):
            results.append(
                {
                    "port": int(port),
                    "protocol": proto,
                    "state": state,
                    "service": service.strip() or None,
                    "version": version.strip() or None,
                }
            )
    return results
