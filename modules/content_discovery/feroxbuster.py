"""feroxbuster wrapper — recursive directory/file discovery (module 15)."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from core.logging import logger
from modules.content_discovery.wordlist_selector import wordlist_path
from modules.exec import iter_jsonl, run_tool

Runner = Callable[..., Awaitable[list[dict]]]


async def _default_runner(binary: str, args, *, timeout: float, stdin: str | None = None):
    """Run feroxbuster and parse its JSONL. Unlike the generic ``run_tool_jsonl``,
    this surfaces WHY a run produced nothing (exit code + stderr) — feroxbuster
    exiting instantly with no output was invisible before."""
    run = await run_tool(binary, args, timeout=timeout, stdin=stdin, check=False)
    rows = list(iter_jsonl(run.stdout))
    if not rows and (run.returncode != 0 or not run.stdout.strip()):
        diag = (run.stderr or run.stdout).strip().splitlines()
        logger.warning(
            "feroxbuster produced no results (exit {}): {}",
            run.returncode,
            diag[-1][:300] if diag else "no output on stdout/stderr",
        )
    return rows


async def discover(
    url: str, wordlist: str, timeout: float, *, runner: Runner = _default_runner
) -> list[dict]:
    """Return discovered ``{url, status, content_length}`` entries for *url*.

    The caller passes a logical wordlist *name*; for the real tool we resolve it to
    an absolute path (a bare filename makes feroxbuster fail instantly with no
    output). Injected runners (tests) get the value untouched. content_discovery
    guards up-front that wordlists are installed."""
    args = [
        "-u",
        url,
        "-w",
        wordlist,
        # `--json` REQUIRES one of --output/--debug-log/--silent, else feroxbuster
        # exits 2 with a clap error. `--silent` emits the JSONL to stdout with logging
        # off — exactly what we parse. (-k insecure, -n no recursion.)
        "--json",
        "--silent",
        "-k",
        "-n",
    ]
    if runner is _default_runner:
        wordlist = wordlist_path(wordlist)
        args[3] = wordlist  # resolved absolute path (index of the -w value)
        # self-bound so a big wordlist returns partial results at the budget rather
        # than being hard-killed (which loses everything).
        args += ["--time-limit", f"{max(int(timeout), 1)}s"]
    rows = await runner("feroxbuster", args, timeout=timeout + 15)
    results: list[dict] = []
    for r in rows:
        if r.get("type") == "response" and r.get("url"):
            results.append(
                {
                    "url": r["url"],
                    "status": r.get("status"),
                    "content_length": r.get("content_length"),
                }
            )
    return results
