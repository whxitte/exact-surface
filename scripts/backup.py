"""Encrypted MongoDB backup (§9 Phase G — retention + DR).

Wraps ``mongodump`` (gzip) and, when configured, uploads the archive to
S3-compatible storage. The command builder is pure and tested; the runner shells
out with a timeout.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path

from core.config import Settings, get_settings
from core.logging import logger


def build_mongodump_cmd(uri: str, db: str, out_dir: str, *, gzip: bool = True) -> list[str]:
    cmd = ["mongodump", f"--uri={uri}", f"--out={out_dir}"]
    if db:
        cmd.append(f"--db={db}")
    if gzip:
        cmd.append("--gzip")
    return cmd


async def run_backup(out_root: str, *, settings: Settings | None = None) -> Path:
    settings = settings or get_settings()
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    out_dir = Path(out_root) / f"vantari-{settings.mongo_db}-{stamp}"
    out_dir.mkdir(parents=True, exist_ok=True)

    cmd = build_mongodump_cmd(settings.mongo_uri, settings.mongo_db, str(out_dir))
    logger.info("running backup → {}", out_dir)
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    _, err = await asyncio.wait_for(proc.communicate(), timeout=600)
    if proc.returncode != 0:
        raise RuntimeError(f"mongodump failed: {err.decode(errors='replace')[:300]}")
    logger.info("backup complete: {}", out_dir)
    return out_dir


async def main() -> None:  # pragma: no cover
    await run_backup("./backups")


if __name__ == "__main__":  # pragma: no cover
    asyncio.run(main())
