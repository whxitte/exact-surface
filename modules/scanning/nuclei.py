"""Nuclei wrapper — templated detection with the v1 SAFE policy (module 7, §9d).

The safe policy is enforced *here*, not left to callers: templates tagged
``dos``, ``intrusive``, or ``fuzz`` are always excluded, so continuous scanning
never sends state-changing or denial-of-service payloads. ``aggressive=True`` (only
ever passed for confirmed-dedicated targets) widens the template set but keeps the
same exclusions — detection only, never exploitation.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable, Iterable

from core.logging import logger
from modules.exec import stream_tool

Runner = Callable[..., Awaitable[list[dict]]]

#: nuclei's own default is 150 rps. This is not it (§3.8b, ADR-0013).
DEFAULT_RATE = 10

#: Never run these tag classes — they are aggressive/harmful (§9d, §3.10).
SAFE_EXCLUDE_TAGS = ("dos", "intrusive", "fuzz")


def _normalize(r: dict) -> dict:
    """nuclei JSONL row → our finding shape."""
    info = r.get("info") or {}
    # What the template actually matched — for Wappalyzer/tech-detection templates this
    # is the concrete tech names (e.g. "nginx, php, cloudflare"); otherwise the matcher
    # name. Surfaced so a finding says WHAT it found, not just "Technology Detection".
    extracted = [str(x) for x in (r.get("extracted-results") or []) if x]
    matched = ", ".join(dict.fromkeys(extracted)) or (r.get("matcher-name") or "")
    return {
        "template_id": r.get("template-id") or r.get("templateID") or "unknown",
        "name": info.get("name", ""),
        "severity": (info.get("severity") or "info").lower(),
        "matched_at": r.get("matched-at") or r.get("host") or "",
        "description": info.get("description", "") or "",
        "reference": info.get("reference") or [],
        "matched": matched,
        "raw": r,
    }


async def _default_runner(
    binary: str, args, *, timeout: float, stdin: str | None = None, on_finding=None
):
    """Run nuclei with LIVE output: each finding + its periodic ``-stats`` progress
    are logged as they happen (so you can see it working in the worker logs), and on
    timeout whatever it found so far is kept rather than discarded.

    ``on_finding`` (async) is called for each finding the instant nuclei emits it, so
    the caller can persist it immediately — findings show up in the UI in real time
    instead of only after the whole batch completes."""
    rows: list[dict] = []
    pending: list[asyncio.Task] = []

    def on_stdout(line: str) -> None:
        line = line.strip()
        if not line:
            return
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            return
        if isinstance(obj, dict):
            rows.append(obj)
            info = obj.get("info") or {}
            logger.info(
                "nuclei ⚑ [{}] {} — {}",
                (info.get("severity") or "info"),
                info.get("name") or obj.get("template-id") or "?",
                obj.get("matched-at") or obj.get("host") or "",
            )
            if on_finding is not None:  # persist this finding right now, don't wait
                pending.append(asyncio.ensure_future(on_finding(_normalize(obj))))

    def on_stderr(line: str) -> None:
        # nuclei is very chatty on stderr: the ASCII banner, version lines, and a
        # flood of "[INF] Skipped … unresponsive" per dead host. Surface only what's
        # useful — the -stats progress JSON ({…}) and real warnings/errors — so the
        # live-log panel isn't drowned in noise.
        line = line.strip()
        if not line:
            return
        if line.startswith("{") or "[WRN]" in line or "[ERR]" in line or "[FTL]" in line:
            logger.info("nuclei: {}", line[:300])

    rc, _out, stderr, timed_out = await stream_tool(
        binary, args, timeout=timeout, stdin=stdin, on_stdout=on_stdout, on_stderr=on_stderr
    )
    if pending:  # make sure every streamed finding finished persisting
        await asyncio.gather(*pending, return_exceptions=True)
    if timed_out:
        logger.warning(
            "nuclei hit the {:.0f}s budget — keeping {} finding(s) found so far", timeout, len(rows)
        )
    elif not rows and rc != 0 and stderr.strip():
        logger.warning(
            "nuclei exited {} with no output — {}", rc, stderr.strip().splitlines()[-1][:200]
        )
    return rows


#: The passive-leaning baseline for HTTP-layer-only targets. Tech-specific product
#: tags (core.tech_tags) are unioned onto this per run, never replacing it.
SAFE_BASE_TAGS = ("exposure", "misconfig", "tech", "ssl", "cve", "default-login")


async def scan(
    urls: list[str],
    timeout: float,
    *,
    aggressive: bool = False,
    rate: int = DEFAULT_RATE,
    extra_tags: Iterable[str] = (),
    runner: Runner = _default_runner,
    on_finding=None,
) -> list[dict]:
    """Scan *urls* and return normalised findings.

    Non-aggressive runs restrict to passive/safe template tags; aggressive runs
    allow the broader set but still exclude the harmful tags above. ``extra_tags``
    (from :func:`core.tech_tags.nuclei_tags_for`) are product tags for the detected
    tech stack; they are *added* to the safe baseline on non-aggressive runs so a
    WordPress/Jenkins/… host gets its relevant templates without widening to the full
    library. They never touch the harmful-tag exclusion, and are a no-op on aggressive
    runs (which already run the full library). ``on_finding`` (async) is invoked per
    finding as nuclei emits it, for real-time persistence (only wired for the real
    runner; injected test runners get the batch return)."""
    urls = [u for u in urls if u]
    if not urls:
        return []

    # -stats + interval so progress streams to the logs; -c widens template
    # concurrency to finish a big URL set in reasonable time.
    #
    # -c and -rl are different controls and both are needed: -c bounds how many
    # templates run at once, -rl bounds how fast requests actually leave. 50
    # concurrent templates with nuclei's default 150 rps is what the §3.8b cap
    # exists to prevent; concurrency is fine once the rate is bounded (ADR-0013).
    args = [
        "-jsonl",
        "-no-color",
        "-duc",
        "-stats",
        "-si",
        "20",
        "-c",
        "50",
        "-rl",
        str(rate),
        "-etags",
        ",".join(SAFE_EXCLUDE_TAGS),
    ]
    if not aggressive:
        # HTTP-layer-only targets: passive-leaning baseline, plus any tech-specific
        # product tags for what httpx fingerprinted — added, never replacing the
        # baseline, so coverage only grows. Sorted for a deterministic command.
        tags = list(SAFE_BASE_TAGS) + sorted(set(extra_tags) - set(SAFE_BASE_TAGS))
        args += ["-tags", ",".join(tags)]

    if runner is _default_runner:
        rows = await runner(
            "nuclei", args, timeout=timeout, stdin="\n".join(urls), on_finding=on_finding
        )
    else:  # injected runner (tests) — plain signature, no real-time hook
        rows = await runner("nuclei", args, timeout=timeout, stdin="\n".join(urls))
    return [_normalize(r) for r in rows]
