"""Encrypted backup: retention, encryption policy, restore (§7 Phase G, §9).

What this database holds is a map of customers' external attack surface — every
host, open port and unfixed finding. A plaintext dump of it is arguably a better
target than the live system.

The previous module docstring claimed "Encrypted MongoDB backup" that "uploads the
archive to S3-compatible storage". It did neither: `mongodump --gzip` into a local
directory. Compression is not encryption, and a backup on the database's own host
is not a backup. `mongodump` was also installed in no image, so it could not run at
all.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from core.config import Settings
from scripts.backup import (
    ARCHIVE_SUFFIX,
    archive_name,
    build_age_decrypt_cmd,
    build_age_encrypt_cmd,
    build_mongorestore_cmd,
    plan_prune,
    resolve_recipient,
)

NOW = datetime(2026, 7, 17, 12, 0, tzinfo=UTC)


def _archive(stamp: str) -> Path:
    return Path(f"/b/vantari-vantari-{stamp}{ARCHIVE_SUFFIX}")


# -- encryption policy -------------------------------------------------------
def test_prod_refuses_to_write_an_unencrypted_backup():
    """An unencrypted dump of every customer's attack surface is a worse artefact
    than no backup at all — so this fails loudly rather than quietly producing one."""
    with pytest.raises(RuntimeError, match="BACKUP_AGE_RECIPIENT"):
        resolve_recipient(Settings(env="prod", backup_age_recipient=None))


def test_dev_without_a_recipient_is_allowed_but_returns_nothing():
    assert resolve_recipient(Settings(env="dev", backup_age_recipient=None)) == ""


def test_recipient_is_used_when_set():
    s = Settings(env="prod", backup_age_recipient="age1abc")
    assert resolve_recipient(s) == "age1abc"


def test_encryption_is_to_a_public_recipient_not_a_local_password():
    """The property worth protecting: this host encrypts to a public key and holds
    no private key, so compromising the scanner does not yield the backup history.
    A passphrase flag here would quietly destroy that."""
    cmd = build_age_encrypt_cmd("age1xyz")
    assert cmd == ["age", "--recipient", "age1xyz"]
    assert "--passphrase" not in cmd


def test_decrypt_needs_an_identity_file():
    assert build_age_decrypt_cmd("/keys/id.txt") == [
        "age",
        "--decrypt",
        "--identity",
        "/keys/id.txt",
    ]


# -- restore -----------------------------------------------------------------
def test_restore_does_not_drop_by_default():
    """Restoring over a live database is destructive; the default for a command
    someone runs at 3am must not delete anything."""
    assert "--drop" not in build_mongorestore_cmd("mongodb://x")
    assert "--drop" in build_mongorestore_cmd("mongodb://x", drop=True)


def test_restore_reads_the_archive_from_stdin():
    cmd = build_mongorestore_cmd("mongodb://x")
    assert "--archive" in cmd and not any(a.startswith("--archive=") for a in cmd)


# -- retention (§9) ----------------------------------------------------------
def test_expired_archives_are_pruned():
    old, fresh = _archive("20260101T000000Z"), _archive("20260716T000000Z")
    plan = plan_prune([old, fresh], retention_days=30, now=NOW)
    assert plan.delete == (old,)
    assert fresh in plan.keep


def test_retention_never_deletes_the_last_backup():
    """The disaster this guards: backups start failing silently, every archive ages
    past retention, and the retention job cheerfully deletes the last good copy."""
    ancient = [_archive("20200101T000000Z"), _archive("20200102T000000Z")]
    plan = plan_prune(ancient, retention_days=1, now=NOW)
    assert len(plan.keep) >= 1
    assert plan.keep[0] == _archive("20200102T000000Z")  # keeps the NEWEST


def test_prune_ignores_files_it_does_not_own():
    """Never delete something just because it shares a directory."""
    stranger = Path("/b/important-not-ours.tar.gz")
    plan = plan_prune([stranger, _archive("20200101T000000Z")], retention_days=1, now=NOW)
    assert stranger not in plan.delete and stranger not in plan.keep


def test_unparseable_timestamps_are_kept_not_deleted():
    """Fail safe: if the name doesn't parse, we don't know its age — keeping an
    extra archive is free, deleting an unknown one is not."""
    weird = Path(f"/b/vantari-db-notatimestamp{ARCHIVE_SUFFIX}")
    plan = plan_prune([_archive("20260716T000000Z"), weird], retention_days=30, now=NOW)
    assert weird not in plan.delete


def test_age_is_read_from_the_name_not_the_mtime():
    """Shipping archives offsite copies them, which rewrites mtimes — that would
    make old backups look fresh, or fresh ones look expired and get deleted."""
    old = _archive("20200101T000000Z")
    plan = plan_prune([old, _archive("20260717T000000Z")], retention_days=30, now=NOW)
    assert old in plan.delete  # decided purely by filename, no filesystem access


def test_archive_name_is_timestamp_sortable():
    name = archive_name("vantari", NOW)
    assert name == f"vantari-vantari-20260717T120000Z{ARCHIVE_SUFFIX}"
    earlier = archive_name("vantari", datetime(2026, 1, 1, tzinfo=UTC))
    assert earlier < name  # lexical order == chronological order; prune relies on it
