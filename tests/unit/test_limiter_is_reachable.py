"""Guards against the limiter silently becoming dead code again (ADR-0012).

The politeness limiter shipped fully built and entirely unreachable: correct bucket
math, correct Redis Lua, comprehensive unit tests — and no caller. `build_limiter`
defaulted to an in-memory store, the worker never passed anything else, and so the
"global ceiling, regardless of how many concurrent jobs touch a target" that
`core/ratelimit.py` promises was enforced per-process. With replicas: 2 in compose
and 3 in Helm, the real per-target rate was 2-3x the configured cap.

No behavioural test catches that, because the failure is an *absence*. These read
the wiring itself.
"""

from __future__ import annotations

from pathlib import Path

from core.config import Settings
from core.ratelimit import DegradingBucketStore, InMemoryBucketStore, build_limiter

ROOT = Path(__file__).resolve().parents[2]


def test_worker_builds_a_shared_store_when_given_redis():
    """The deployed path. An in-memory store here means every replica gets its own
    bucket and N workers emit N x the per-target ceiling."""
    limiter = build_limiter(Settings(), redis=object())
    assert isinstance(limiter._store, DegradingBucketStore)


def test_worker_falls_back_to_local_only_without_redis():
    """Dev/tests genuinely have no fleet — but this is the default that hid the bug,
    so it stays pinned rather than incidental."""
    limiter = build_limiter(Settings())
    assert isinstance(limiter._store, InMemoryBucketStore)


def test_worker_startup_passes_redis_to_the_limiter():
    """The actual regression: build_limiter supported a shared store all along and
    startup() simply never passed one. Read from source — taskqueue.worker needs arq,
    which is not installed in the test venv."""
    src = (ROOT / "taskqueue/worker.py").read_text()
    assert "build_limiter(settings, redis=redis)" in src, (
        "worker startup no longer passes redis — the ceiling is per-process again"
    )


def test_worker_refuses_to_start_without_a_shared_store_in_prod():
    """Fail closed: not scanning is recoverable, an AUP breach that terminates the
    cloud account is not."""
    src = (ROOT / "taskqueue/worker.py").read_text()
    assert "settings.is_prod" in src and "RuntimeError" in src


def test_the_limiter_has_a_caller():
    """The root cause, stated directly. If nothing outside core/ and tests ever
    acquires budget, the limiter is decoration again."""
    callers = []
    for d in ("pipelines", "modules", "taskqueue", "api"):
        for path in (ROOT / d).rglob("*.py"):
            text = path.read_text()
            if "throttled_fetch(" in text or ".acquire(" in text:
                callers.append(path.name)
    assert callers, "nothing calls the politeness limiter — it is dead code again"


def test_in_process_target_fetchers_are_throttled():
    """The two pipelines that make in-process HTTP at customer hosts. A new one that
    forgets this wrapper re-opens the hole, so name them explicitly."""
    for rel in ("pipelines/takeover.py", "pipelines/secrets.py"):
        src = (ROOT / rel).read_text()
        assert "throttled_fetch(fetch, limiter)" in src, f"{rel} fetches without pacing"
