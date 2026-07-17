"""feroxbuster wrapper — recursive directory/file discovery (module 15)."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from core.logging import logger
from modules.content_discovery.wordlist_selector import wordlist_path
from modules.exec import iter_jsonl, run_tool

Runner = Callable[..., Awaitable[list[dict]]]

#: feroxbuster applies NO rate limit by default. This is not that (§3.8b, ADR-0013).
DEFAULT_RATE = 10


class TargetUnreachable(Exception):
    """feroxbuster's HTTP client couldn't connect to the target — a client-level failure
    (often IPv6 happy-eyeballs or TLS-fingerprint quirks) that Go-based tools like ffuf /
    httpx don't hit. The caller retries the host with ffuf."""


async def _default_runner(binary: str, args, *, timeout: float, stdin: str | None = None):
    """Run feroxbuster and parse its JSONL. Unlike the generic ``run_tool_jsonl``,
    this surfaces WHY a run produced nothing (exit code + stderr) — feroxbuster
    exiting instantly with no output was invisible before."""
    run = await run_tool(binary, args, timeout=timeout, stdin=stdin, check=False)
    rows = list(iter_jsonl(run.stdout))
    if not rows:
        stderr = run.stderr or ""
        if "could not connect" in stderr.lower():
            # feroxbuster can't reach a host httpx already probed alive — hand it to ffuf.
            raise TargetUnreachable(stderr.strip().splitlines()[-1][:200])
        diag = stderr.strip().splitlines()
        if diag:  # some other real error
            logger.warning(
                "feroxbuster produced no results (exit {}): {}", run.returncode, diag[-1][:300]
            )
        else:  # ran fine, this host just has no discoverable paths — not an error
            logger.debug("feroxbuster: no paths on this host (exit {})", run.returncode)
    return rows


async def discover(
    url: str,
    wordlist: str,
    timeout: float,
    *,
    rate: int = DEFAULT_RATE,
    runner: Runner = _default_runner,
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
        # feroxbuster defaults to 50 threads; with 10 hosts scanned at once that's ~500
        # concurrent connections. Fewer threads eases the load; a 10s connect timeout
        # fails fast on a host feroxbuster's client can't reach so we fall back to ffuf.
        "-t",
        "25",
        "-T",
        "10",
        # Threads bound CONCURRENCY, not rate — 25 threads with feroxbuster's default
        # of no rate limit still empties a wordlist at the host as fast as it will
        # answer. Content discovery brute-forces thousands of paths, so this is the
        # most abusive thing we run; --rate-limit is what actually caps it (ADR-0013).
        # Documented as per-directory: `-n` (no recursion) keeps that ≈ per-target.
        "--rate-limit",
        str(rate),
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
