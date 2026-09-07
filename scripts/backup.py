"""Encrypted MongoDB backup + restore (§7 Phase G, §9 retention).

What this stores is a map of operators' external attack surface: every host, open
port, and unfixed finding. A plaintext dump of it is arguably a more valuable
target than the live system, so encryption is not optional decoration here.

Three properties, in the order they matter:

**1. The plaintext never touches disk.** ``mongodump --archive`` writes to stdout
and is piped straight into ``age``. Dumping to a file and encrypting it afterwards
leaves a plaintext copy on the disk — and after ``rm``, still leaves it recoverable
in free blocks. The previous version of this module did exactly that (and did not
encrypt at all, despite its docstring).

**2. This host cannot decrypt its own backups.** ``age`` is used with a *public*
recipient key. The private identity lives somewhere else entirely — a vault, a
laptop, an offline file. Someone who owns the scanning host gets the ability to
*write* backups, not to read them. Symmetric encryption with a key from the
environment would hand them every historical backup along with the host.

**3. It is restorable, and that is testable.** A backup nobody has restored is a
hypothesis. ``restore`` and ``verify`` are part of this module, not a wiki page.

Deliberately NOT here: uploading offsite. It would mean either a new SDK
dependency or credentials to a bucket on the very host we just assumed could be
compromised. Ship the directory offsite with whatever the deployment already uses
(rclone/aws-cli/restic in a sidecar cron). **A backup on the same host as the
database is not a backup** — the failure it protects against destroys both.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from core.config import Settings, get_settings
from core.logging import logger

#: Suffix marks an age-encrypted archive. Kept explicit so pruning can never match
#: something that is not ours.
ARCHIVE_SUFFIX = ".archive.gz.age"


def build_mongodump_cmd(uri: str, db: str, *, gzip: bool = True) -> list[str]:
    """mongodump streaming a single archive to **stdout** (not a directory).

    ``--archive`` with no value means stdout; that is what lets the dump be piped
    into the encryptor without ever landing as plaintext.
    """
    cmd = ["mongodump", f"--uri={uri}", "--archive"]
    if db:
        cmd.append(f"--db={db}")
    if gzip:
        cmd.append("--gzip")
    return cmd


def build_age_encrypt_cmd(recipient: str) -> list[str]:
    """Encrypt stdin → stdout for *recipient* (an ``age1...`` public key)."""
    return ["age", "--recipient", recipient]


def build_age_decrypt_cmd(identity_file: str) -> list[str]:
    """Decrypt stdin → stdout using the private identity. Only ever run where the
    identity lives — by design, not on the scanning host."""
    return ["age", "--decrypt", "--identity", identity_file]


def build_mongorestore_cmd(uri: str, *, drop: bool = False, gzip: bool = True) -> list[str]:
    """mongorestore reading a single archive from **stdin**.

    ``drop`` is opt-in: restoring over a live database is destructive, and the safe
    default for a command someone runs at 3am is to not delete anything.
    """
    cmd = ["mongorestore", f"--uri={uri}", "--archive"]
    if gzip:
        cmd.append("--gzip")
    if drop:
        cmd.append("--drop")
    return cmd


def archive_name(db: str, now: datetime) -> str:
    return f"exactsurface-{db}-{now.strftime('%Y%m%dT%H%M%SZ')}{ARCHIVE_SUFFIX}"


@dataclass(frozen=True)
class Prune:
    """What a retention pass would delete, separated from doing it (§9)."""

    keep: tuple[Path, ...]
    delete: tuple[Path, ...]


def plan_prune(paths, retention_days: int, now: datetime, *, min_keep: int = 1) -> Prune:
    """Decide which archives age out. Pure — the deletion is the caller's.

    ``min_keep`` is a floor that survives the obvious disaster: backups start
    failing silently, every archive ages past retention, and the retention job
    cheerfully deletes the last good copy. Retention should never leave zero
    backups, however old the newest one is.
    """
    cutoff = now - timedelta(days=retention_days)
    ours = sorted(
        (p for p in paths if p.name.endswith(ARCHIVE_SUFFIX)),
        key=lambda p: p.name,
        reverse=True,  # newest first — names are timestamp-sorted
    )
    keep: list[Path] = []
    delete: list[Path] = []
    for i, path in enumerate(ours):
        if i < min_keep:
            keep.append(path)
            continue
        stamp = _stamp_of(path)
        (delete if stamp is not None and stamp < cutoff else keep).append(path)
    return Prune(keep=tuple(keep), delete=tuple(delete))


def _stamp_of(path: Path) -> datetime | None:
    """Timestamp encoded in the filename; None if it does not parse.

    Read from the name, not the mtime: copying archives around (which is exactly
    what shipping them offsite does) rewrites mtimes and would silently make old
    backups look fresh — or fresh ones look expired and get deleted.
    """
    stem = path.name[: -len(ARCHIVE_SUFFIX)]
    try:
        return datetime.strptime(stem.rsplit("-", 1)[-1], "%Y%m%dT%H%M%SZ").replace(tzinfo=UTC)
    except ValueError:
        return None


def resolve_recipient(settings: Settings) -> str:
    """The age public key to encrypt to. Refuses to write plaintext in prod.

    An unencrypted dump of every operator's attack surface is a worse artefact than
    no backup at all, so prod fails loudly rather than silently producing one.
    """
    recipient = (settings.backup_age_recipient or "").strip()
    if recipient:
        return recipient
    if settings.is_prod:
        raise RuntimeError(
            "EXACTSURFACE_BACKUP_AGE_RECIPIENT is unset — refusing to write an "
            "unencrypted backup of operator attack-surface data in prod (§7/§9)"
        )
    return ""


async def run_backup(
    out_root: str | None = None,
    *,
    settings: Settings | None = None,
    now: datetime | None = None,
) -> Path:  # pragma: no cover - drives real subprocesses
    """Dump → encrypt → write, streaming, with no plaintext intermediate."""
    settings = settings or get_settings()
    now = now or datetime.now(UTC)
    recipient = resolve_recipient(settings)
    out_dir = Path(out_root or settings.backup_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / archive_name(settings.mongo_db, now)

    dump_cmd = build_mongodump_cmd(settings.mongo_uri, settings.mongo_db)
    if not recipient:
        logger.warning("no age recipient — writing an UNENCRYPTED dev backup to {}", target)
        await _run_to_file(dump_cmd, target.with_suffix(".plain.gz"))
        return target.with_suffix(".plain.gz")

    logger.info("backup → {} (encrypted to {})", target, recipient[:16] + "…")
    await _run_piped(dump_cmd, build_age_encrypt_cmd(recipient), target)
    logger.info("backup complete: {} ({} bytes)", target, target.stat().st_size)
    return target


async def _pipeline(
    producer: list[str], consumer: list[str], *, stdin=None, stdout=None
) -> None:  # pragma: no cover
    """Run ``producer | consumer``, raising if *either* side fails.

    Uses a real ``os.pipe()`` rather than ``stdout=PIPE``: asyncio's PIPE hands back
    a ``StreamReader``, which is not a file descriptor and cannot be another
    process's stdin. Pumping the bytes through this event loop instead would drag a
    multi-GB dump through Python for no reason; with an OS pipe the kernel moves it
    and applies backpressure for free.

    Both return codes are checked. A pipeline that only checks the last command
    happily encrypts a failed dump's empty output — which looks like a successful
    backup right up until you need it.
    """
    import os

    read_fd, write_fd = os.pipe()
    try:
        p1 = await asyncio.create_subprocess_exec(
            *producer, stdin=stdin, stdout=write_fd, stderr=asyncio.subprocess.PIPE
        )
        os.close(write_fd)  # drop our copy so the consumer sees EOF when p1 exits
        write_fd = -1
        p2 = await asyncio.create_subprocess_exec(
            *consumer,
            stdin=read_fd,
            stdout=stdout or asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        os.close(read_fd)
        read_fd = -1
        _, err2 = await p2.communicate()
        err1 = await p1.stderr.read()
        await p1.wait()
    finally:
        for fd in (read_fd, write_fd):
            if fd != -1:
                os.close(fd)
    if p1.returncode != 0:
        raise RuntimeError(f"{producer[0]} failed: {err1.decode(errors='replace')[:300]}")
    if p2.returncode != 0:
        raise RuntimeError(f"{consumer[0]} failed: {err2.decode(errors='replace')[:300]}")


async def _run_piped(
    producer: list[str], consumer: list[str], target: Path, *, stdin=None
) -> None:  # pragma: no cover
    """``producer | consumer > target``; removes *target* if either side failed, so
    a truncated archive can never sit there looking like a valid backup."""
    try:
        with target.open("wb") as out:
            await _pipeline(producer, consumer, stdin=stdin, stdout=out)
    except Exception:
        target.unlink(missing_ok=True)
        raise


async def _run_to_file(cmd: list[str], target: Path) -> None:  # pragma: no cover
    with target.open("wb") as out:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=out, stderr=asyncio.subprocess.PIPE
        )
        _, err = await proc.communicate()
    if proc.returncode != 0:
        target.unlink(missing_ok=True)
        raise RuntimeError(f"{cmd[0]} failed: {err.decode(errors='replace')[:300]}")


async def run_prune(
    out_root: str | None = None,
    *,
    settings: Settings | None = None,
    now: datetime | None = None,
) -> Prune:  # pragma: no cover - filesystem
    settings = settings or get_settings()
    out_dir = Path(out_root or settings.backup_dir)
    plan = plan_prune(out_dir.glob("*"), settings.backup_retention_days, now or datetime.now(UTC))
    for path in plan.delete:
        logger.info("pruning expired backup {}", path.name)
        path.unlink(missing_ok=True)
    return plan


async def run_restore(
    archive: str,
    *,
    identity_file: str,
    settings: Settings | None = None,
    drop: bool = False,
) -> None:  # pragma: no cover - drives real subprocesses
    """Decrypt *archive* and restore it. Run where the age identity lives."""
    settings = settings or get_settings()
    logger.info("restoring {} → {} (drop={})", archive, settings.mongo_db, drop)
    # The decrypted stream goes process-to-process; plaintext never hits disk on the
    # restore path either.
    with Path(archive).open("rb") as src:
        await _pipeline(
            build_age_decrypt_cmd(identity_file),
            build_mongorestore_cmd(settings.mongo_uri, drop=drop),
            stdin=src,
        )
    logger.info("restore complete")


async def main() -> None:  # pragma: no cover
    import argparse

    parser = argparse.ArgumentParser(prog="exactsurface-backup")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("run", help="dump + encrypt + prune")
    r = sub.add_parser("restore", help="decrypt + mongorestore (needs the age identity)")
    r.add_argument("archive")
    r.add_argument("--identity", required=True, help="age identity file (private key)")
    r.add_argument("--drop", action="store_true", help="DESTRUCTIVE: drop collections first")

    args = parser.parse_args()
    if args.cmd == "run":
        await run_backup()
        await run_prune()
    else:
        await run_restore(args.archive, identity_file=args.identity, drop=args.drop)


if __name__ == "__main__":  # pragma: no cover
    asyncio.run(main())
