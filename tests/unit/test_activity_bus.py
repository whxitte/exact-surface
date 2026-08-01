"""Live activity bus: ScanRun saves publish; no bus configured is a safe no-op."""

from __future__ import annotations

from core import activity_bus
from core.models import ScanRun, ScanStatus
from db.audit import ScanRunRepo
from tests.fakes import FakeMongo


class FakeBus:
    def __init__(self) -> None:
        self.published: list[tuple[str, dict]] = []

    async def publish(self, tenant_id: str, run: dict) -> None:
        self.published.append((tenant_id, run))


async def test_save_publishes_when_bus_set():
    bus = FakeBus()
    activity_bus.set_bus(bus)
    try:
        mongo = FakeMongo()
        await ScanRunRepo.from_mongo(mongo).save(
            ScanRun(
                tenant_id="t1", scan_id="s1", program_id="p1",
                pipeline="full", status=ScanStatus.RUNNING,
            )
        )
    finally:
        activity_bus.set_bus(None)

    assert len(bus.published) == 1
    tenant_id, run = bus.published[0]
    assert tenant_id == "t1"
    assert run["scan_id"] == "s1" and run["status"] == "running"


async def test_save_is_noop_without_bus():
    activity_bus.set_bus(None)
    mongo = FakeMongo()
    # must not raise even though nothing is listening
    await ScanRunRepo.from_mongo(mongo).save(
        ScanRun(tenant_id="t1", scan_id="s1", program_id="p1", pipeline="full")
    )
    saved = await ScanRunRepo.from_mongo(mongo).list("t1")
    assert len(saved) == 1


def test_format_log_line():
    from datetime import datetime
    from types import SimpleNamespace

    from core.activity_bus import format_log_line

    rec = {
        "time": datetime(2026, 7, 5, 13, 20, 18),
        "level": SimpleNamespace(name="INFO"),
        "extra": {"pipeline": "crawl"},
        "message": "katana crawling x.com",
    }
    line = format_log_line(rec)
    assert "13:20:18" in line and "INFO" in line
    assert "[crawl]" in line and "katana crawling x.com" in line


async def test_publish_swallows_bus_errors():
    class Boom:
        async def publish(self, *_a):
            raise RuntimeError("redis down")

    activity_bus.set_bus(Boom())
    try:
        # publish_run must never propagate — a scan can't fail because the bus is down
        await activity_bus.publish_run("t1", {"scan_id": "s1"})
    finally:
        activity_bus.set_bus(None)


async def test_log_push_tasks_are_held_until_they_finish():
    """A dropped log line is the hardest kind of bug to attribute: nothing errors, the
    scan succeeds, and the user just sees half a log.

    `loop.create_task` returns a task the event loop holds only a WEAK reference to, so
    without a strong reference the push can be garbage-collected mid-flight. This
    asserts the reference set exists, is populated while a push is in flight, and is
    drained afterwards so it cannot become a leak.
    """
    import asyncio

    from core import activity_bus as ab

    started = asyncio.Event()
    release = asyncio.Event()
    pushed: list[tuple[str, str]] = []

    class SlowBus:
        async def push_log(self, scan_id: str, line: str) -> None:
            started.set()
            await release.wait()
            pushed.append((scan_id, line))

    from core.logging import bind_context, configure_logging, logger

    # The sink reads scan_id from record["extra"], which is populated by the loguru
    # patcher that configure_logging installs. Production calls it at startup; without
    # it the sink sees an empty extra and correctly does nothing.
    configure_logging()
    ab.set_bus(SlowBus())
    ab._capture_installed = False
    ab._inflight_pushes.clear()
    try:
        ab.install_scan_log_capture()

        with bind_context(scan_id="scan-held", pipeline="probe"):
            logger.info("a line that must not be lost")

        await asyncio.wait_for(started.wait(), timeout=2)
        assert ab._inflight_pushes, "the push task is not referenced — it can be GC'd"

        release.set()
        for _ in range(100):
            if not ab._inflight_pushes:
                break
            await asyncio.sleep(0.01)

        assert pushed and pushed[0][0] == "scan-held"
        assert not ab._inflight_pushes, "finished tasks are not discarded — this leaks"
    finally:
        ab.set_bus(None)
        ab._capture_installed = False
        ab._inflight_pushes.clear()
