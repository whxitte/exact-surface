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
