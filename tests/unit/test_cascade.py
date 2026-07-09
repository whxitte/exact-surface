"""Event-driven cascade: DAG fan-out + target-scoped pipeline execution."""

from __future__ import annotations

from taskqueue.cascade import cascade_jobs
from taskqueue.jobs import Priority


# -- cascade DAG -------------------------------------------------------------
def test_ingest_new_hosts_cascade_to_probe():
    jobs = cascade_jobs(
        pipeline="ingest",
        result={"new": 2, "cascade_targets": ["a.acme.com", "b.acme.com"]},
        tenant_id="t1",
        program_id="p1",
    )
    assert len(jobs) == 1
    j = jobs[0]
    assert j.pipeline == "probe" and j.targets == ("a.acme.com", "b.acme.com")
    assert j.priority == Priority.NEW_ASSET and j.reason == "cascade:ingest"


def test_probe_cascades_to_crawl_and_port_scan_with_targets():
    jobs = cascade_jobs(
        pipeline="probe",
        result={"new": 1, "cascade_targets": ["a.acme.com"]},
        tenant_id="t1",
        program_id="p1",
    )
    assert {j.pipeline for j in jobs} == {"crawl", "port_scan"}
    assert all(j.targets == ("a.acme.com",) for j in jobs)


def test_scan_new_findings_cascade_to_program_wide_notify():
    jobs = cascade_jobs(pipeline="scan", result={"new": 3}, tenant_id="t1", program_id="p1")
    assert len(jobs) == 1
    assert jobs[0].pipeline == "notify" and jobs[0].targets == ()  # notify is program-wide


def test_no_cascade_when_nothing_new():
    # crawl with no new endpoints → no scan/secrets follow-on
    assert (
        cascade_jobs(
            pipeline="crawl",
            result={"new": 0, "cascade_targets": []},
            tenant_id="t1",
            program_id="p1",
        )
        == []
    )
    # scan with no new findings → no notify
    assert cascade_jobs(pipeline="scan", result={"new": 0}, tenant_id="t1", program_id="p1") == []


def test_skipped_phase_does_not_cascade():
    assert (
        cascade_jobs(
            pipeline="probe",
            result={"skipped": True, "note": "no assets"},
            tenant_id="t1",
            program_id="p1",
        )
        == []
    )


def test_terminal_phase_has_no_downstream():
    assert cascade_jobs(pipeline="notify", result={"new": 5}, tenant_id="t1", program_id="p1") == []


def test_targeted_job_dedup_key_differs_from_whole_program():
    from taskqueue.jobs import Job

    whole = Job(tenant_id="t1", program_id="p1", pipeline="probe")
    targeted = Job(tenant_id="t1", program_id="p1", pipeline="probe", targets=("a.acme.com",))
    assert whole.dedup_key() != targeted.dedup_key()
    # same target set → same key (collapses duplicate cascades)
    again = Job(tenant_id="t1", program_id="p1", pipeline="probe", targets=("a.acme.com",))
    assert targeted.dedup_key() == again.dedup_key()


# -- target-scoped execution --------------------------------------------------
async def test_probe_targets_scope_run_to_named_hosts():
    """A cascade probe job with targets only probes those hosts, not the whole program."""
    from core.models import Asset
    from core.scope import ProgramScope, ScopeEngine
    from core.tenant import TenantContext
    from db.assets import AssetRepo
    from pipelines.probe import run_probe
    from tests.fakes import FakeMongo

    engine = ScopeEngine.from_data_file()
    scope = ProgramScope(
        verified_apexes=("acme.com",), authorized_dedicated_cidrs=("45.55.0.0/16",)
    )
    mongo = FakeMongo()
    repo = AssetRepo.from_mongo(mongo)
    for host, ip in [("a.acme.com", "45.55.1.1"), ("b.acme.com", "45.55.1.2")]:
        await repo.upsert(
            Asset(
                tenant_id="t1",
                program_id="p1",
                fingerprint=host,
                hostname=host,
                resolved_ips=[ip],
            )
        )

    seen: list[str] = []

    async def capturing_probe(hosts, _timeout):
        seen.extend(hosts)
        return [{"url": f"https://{h}", "status_code": 200} for h in hosts]

    res = await run_probe(
        mongo=mongo,
        engine=engine,
        scope=scope,
        tenant=TenantContext(tenant_id="t1"),
        program_id="p1",
        timeout=10,
        targets={"a.acme.com"},
        probe=capturing_probe,
    )
    assert seen == ["a.acme.com"]  # b.acme.com was not probed
    assert res["cascade_targets"] == ["a.acme.com"]  # feeds crawl/port_scan next
