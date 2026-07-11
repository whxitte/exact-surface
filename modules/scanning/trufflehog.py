"""trufflehog wrapper — robust, *verified* secret detection (module 8, upgrade).

Our regex detector (``core.secrets_policy``) is fast and always-on, but only knows a
handful of patterns and can't tell a live key from a dead one. trufflehog adds 800+
detectors AND live verification — a *verified* hit is a secret that actually works
right now, which we surface as CRITICAL (near-zero false positives).

trufflehog scans files, so the secret scanner writes each fetched body to a temp dir
and we run ``trufflehog filesystem`` over it, mapping results back to their URL. If
the binary isn't installed we return nothing and the regex engine still covers us.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from core.errors import ToolNotFound
from core.logging import logger
from core.severity import Severity
from modules.exec import run_tool_jsonl

Runner = Callable[..., Awaitable[list[dict]]]


def _file_of(row: dict) -> str:
    fs = (((row.get("SourceMetadata") or {}).get("Data") or {}).get("Filesystem")) or {}
    return fs.get("file", "")


async def scan_dir(
    directory: str,
    file_to_url: dict[str, str],
    *,
    timeout: float = 180.0,
    runner: Runner = run_tool_jsonl,
) -> list[dict]:
    """Run trufflehog over *directory* and map hits back to their source URL.

    Returns ``{kind, value, source_locator, severity, verified}`` per hit. Verified
    secrets are CRITICAL; unverified are HIGH. Returns ``[]`` (not an error) when
    trufflehog isn't installed — the regex engine still runs."""
    try:
        rows = await runner(
            "trufflehog",
            ["filesystem", directory, "--json", "--no-update", "--no-verification-http-timeout=8s"],
            timeout=timeout,
        )
    except ToolNotFound:
        logger.warning(
            "trufflehog not installed — secret scan running on regex only "
            "(rebuild Dockerfile.pipeline to enable it)"
        )
        return []
    except Exception as exc:  # noqa: BLE001 - trufflehog failure must not fail the scan
        logger.warning("trufflehog scan failed: {}", exc)
        return []

    hits: list[dict] = []
    for r in rows:
        raw = r.get("Raw") or r.get("RawV2") or ""
        if not raw:
            continue
        verified = bool(r.get("Verified"))
        detector = r.get("DetectorName") or "secret"
        hits.append(
            {
                "kind": f"trufflehog:{detector}".lower(),
                "value": raw,
                "source_locator": file_to_url.get(_file_of(r), _file_of(r)),
                "severity": Severity.CRITICAL if verified else Severity.HIGH,
                "verified": verified,
            }
        )
    n_verified = sum(1 for h in hits if h["verified"])
    # Always log — so a clean run reads as "ran, found nothing" rather than silence
    # (which looked like the tool never executed).
    logger.info(
        "trufflehog: scanned {} staged file(s), {} secret(s) ({} verified live)",
        len(file_to_url),
        len(hits),
        n_verified,
    )
    return hits
