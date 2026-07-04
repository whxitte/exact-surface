"""Nuclei wrapper — templated detection with the v1 SAFE policy (module 7, §9d).

The safe policy is enforced *here*, not left to callers: templates tagged
``dos``, ``intrusive``, or ``fuzz`` are always excluded, so continuous scanning
never sends state-changing or denial-of-service payloads. ``aggressive=True`` (only
ever passed for confirmed-dedicated targets) widens the template set but keeps the
same exclusions — detection only, never exploitation.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from modules.exec import run_tool_jsonl

Runner = Callable[..., Awaitable[list[dict]]]

#: Never run these tag classes — they are aggressive/harmful (§9d, §3.10).
SAFE_EXCLUDE_TAGS = ("dos", "intrusive", "fuzz")


async def scan(
    urls: list[str],
    timeout: float,
    *,
    aggressive: bool = False,
    runner: Runner = run_tool_jsonl,
) -> list[dict]:
    """Scan *urls* and return normalised findings.

    Non-aggressive runs restrict to passive/safe template tags; aggressive runs
    allow the broader set but still exclude the harmful tags above.
    """
    urls = [u for u in urls if u]
    if not urls:
        return []

    args = ["-silent", "-jsonl", "-no-color", "-duc", "-etags", ",".join(SAFE_EXCLUDE_TAGS)]
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
