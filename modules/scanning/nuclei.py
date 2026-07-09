"""Nuclei wrapper — templated detection with the v1 SAFE policy (module 7, §9d).

The safe policy is enforced *here*, not left to callers: templates tagged
``dos``, ``intrusive``, or ``fuzz`` are always excluded, so continuous scanning
never sends state-changing or denial-of-service payloads. ``aggressive=True`` (only
ever passed for confirmed-dedicated targets) widens the template set but keeps the
same exclusions — detection only, never exploitation.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable

from core.logging import logger
from modules.exec import stream_tool

Runner = Callable[..., Awaitable[list[dict]]]

#: Never run these tag classes — they are aggressive/harmful (§9d, §3.10).
SAFE_EXCLUDE_TAGS = ("dos", "intrusive", "fuzz")


async def _default_runner(binary: str, args, *, timeout: float, stdin: str | None = None):
    """Run nuclei with LIVE output: each finding + its periodic ``-stats`` progress
    are logged as they happen (so you can see it working in the worker logs), and on
    timeout whatever it found so far is kept rather than discarded."""
    rows: list[dict] = []

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

    def on_stderr(line: str) -> None:
        # nuclei -stats prints progress here (templates done, requests, matches, ETA)
        line = line.strip()
        if line:
            logger.info("nuclei: {}", line[:300])

    rc, _out, stderr, timed_out = await stream_tool(
        binary, args, timeout=timeout, stdin=stdin, on_stdout=on_stdout, on_stderr=on_stderr
    )
    if timed_out:
        logger.warning(
            "nuclei hit the {:.0f}s budget — keeping {} finding(s) found so far", timeout, len(rows)
        )
    elif not rows and rc != 0 and stderr.strip():
        logger.warning(
            "nuclei exited {} with no output — {}", rc, stderr.strip().splitlines()[-1][:200]
        )
    return rows


async def scan(
    urls: list[str],
    timeout: float,
    *,
    aggressive: bool = False,
    runner: Runner = _default_runner,
) -> list[dict]:
    """Scan *urls* and return normalised findings.

    Non-aggressive runs restrict to passive/safe template tags; aggressive runs
    allow the broader set but still exclude the harmful tags above.
    """
    urls = [u for u in urls if u]
    if not urls:
        return []

    # -stats + interval so progress streams to the logs; -c widens template
    # concurrency to finish a big URL set in reasonable time.
    args = [
        "-jsonl",
        "-no-color",
        "-duc",
        "-stats",
        "-si",
        "20",
        "-c",
        "50",
        "-etags",
        ",".join(SAFE_EXCLUDE_TAGS),
    ]
    if not aggressive:
        # HTTP-layer-only targets: passive-leaning tags, no active exploitation attempts.
        args += ["-tags", "exposure,misconfig,tech,ssl,cve,default-login"]

    rows = await runner("nuclei", args, timeout=timeout, stdin="\n".join(urls))
    findings: list[dict] = []
    for r in rows:
        info = r.get("info") or {}
        findings.append(
            {
                "template_id": r.get("template-id") or r.get("templateID") or "unknown",
                "name": info.get("name", ""),
                "severity": (info.get("severity") or "info").lower(),
                "matched_at": r.get("matched-at") or r.get("host") or "",
                "description": info.get("description", "") or "",
                "reference": info.get("reference") or [],
                "raw": r,
            }
        )
    return findings
