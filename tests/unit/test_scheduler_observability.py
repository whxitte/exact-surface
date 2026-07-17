"""Scheduler liveness signal (§7 Phase G).

``run_forever`` deliberately swallows tick exceptions so one bad tick cannot kill
the loop. The cost is that a scheduler failing *every* tick looks — from outside —
exactly like a healthy one with nothing to do: the process is up, the port answers,
and no scan ever runs again. These pin the signal that tells them apart.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from core.metrics import MetricsRegistry
from taskqueue.scheduler import Scheduler
from tests.fakes import FakeMongo


@pytest.fixture
def reg(monkeypatch):
    """Private registry so assertions don't see samples from other tests."""
    import taskqueue.scheduler as sched

    registry = MetricsRegistry()
    monkeypatch.setattr(sched, "REGISTRY", registry)
    return registry


def _observe(status: str, **kw):
    from taskqueue.scheduler import _observe_tick

    _observe_tick(status, **kw)


def test_a_successful_tick_records_its_timestamp(reg):
    now = datetime(2026, 7, 17, 12, 0, tzinfo=UTC)
    _observe("ok", jobs=0, now=now)

    out = reg.render()
    assert 'vantari_scheduler_ticks_total{status="ok"} 1.0' in out
    assert f"vantari_scheduler_last_success_timestamp {now.timestamp()}" in out


def test_a_failed_tick_does_not_advance_the_success_timestamp(reg):
    """The whole point: `time() - last_success` must keep growing while ticks are
    failing, or the alert that catches a silently-broken scheduler never fires."""
    ok_at = datetime(2026, 7, 17, 12, 0, tzinfo=UTC)
    _observe("ok", now=ok_at)
    _observe("failed", now=datetime(2026, 7, 17, 13, 0, tzinfo=UTC))

    out = reg.render()
    assert 'vantari_scheduler_ticks_total{status="failed"} 1.0' in out
    assert f"vantari_scheduler_last_success_timestamp {ok_at.timestamp()}" in out


def test_an_idle_tick_is_still_a_healthy_tick(reg):
    """Zero jobs due is normal — it must count as alive, not as a stall."""
    _observe("ok", jobs=0)
    out = reg.render()
    assert 'vantari_scheduler_ticks_total{status="ok"} 1.0' in out
    assert "vantari_scheduler_jobs_enqueued_total" not in out


def test_enqueued_jobs_are_counted(reg):
    _observe("ok", jobs=3)
    _observe("ok", jobs=2)
    assert "vantari_scheduler_jobs_enqueued_total 5.0" in reg.render()


async def test_run_once_marks_the_scheduler_alive(reg):
    """Wired-up check: a real (empty) tick must move the liveness gauge, not just
    the helper called directly."""

    async def _enqueue(job):  # no programs exist → never called
        raise AssertionError("nothing should be enqueued")

    scheduler = Scheduler(FakeMongo(), _enqueue)
    assert await scheduler.run_once() == 0
    assert "vantari_scheduler_last_success_timestamp" in reg.render()
