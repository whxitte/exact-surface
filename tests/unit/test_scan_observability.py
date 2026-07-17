"""Scan-run observability (§7 Phase G).

The Phase G exit gate is "runs 7 days unattended ... no intervention". You cannot
claim that without being able to see a stage quietly starting to time out, or a
run's duration creeping toward its budget. These pin that instrumentation, and
that every long-running process actually reports errors.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from core.metrics import MetricsRegistry
from core.models import ScanRun, ScanStage, ScanStatus


def _patched(monkeypatch):
    """Swap in a private registry so assertions don't see other tests' samples."""
    reg = MetricsRegistry()
    import pipelines.orchestrate as orch

    monkeypatch.setattr(orch, "REGISTRY", reg)
    return reg, orch


def test_stage_outcome_and_duration_are_recorded(monkeypatch):
    reg, orch = _patched(monkeypatch)
    start = datetime.now(UTC)
    stage = ScanStage(
        name="scan",
        status=ScanStatus.SUCCESS,
        started_at=start,
        finished_at=start + timedelta(seconds=42),
    )
    orch._observe_stage("scan", "success", stage)

    out = reg.render()
    assert 'vantari_scan_stage_total{stage="scan",status="success"} 1.0' in out
    assert 'vantari_scan_stage_duration_seconds_bucket{stage="scan",le="60"} 1.0' in out
    assert 'vantari_scan_stage_duration_seconds_sum{stage="scan"} 42.0' in out


def test_a_timed_out_stage_is_distinguishable_from_a_failure(monkeypatch):
    """'timeout' vs 'failed' is the difference between "too slow" and "broken" —
    an operator needs to tell them apart without reading logs."""
    reg, orch = _patched(monkeypatch)
    stage = ScanStage(name="port_scan", status=ScanStatus.FAILED)
    orch._observe_stage("port_scan", "timeout", stage)
    orch._observe_stage("port_scan", "failed", stage)

    out = reg.render()
    assert 'vantari_scan_stage_total{stage="port_scan",status="timeout"} 1.0' in out
    assert 'vantari_scan_stage_total{stage="port_scan",status="failed"} 1.0' in out


def test_stage_without_timestamps_records_outcome_but_no_duration(monkeypatch):
    """A stage that never started still counts — it must not crash the observer."""
    reg, orch = _patched(monkeypatch)
    orch._observe_stage("dork", "skipped", ScanStage(name="dork"))
    out = reg.render()
    assert 'vantari_scan_stage_total{stage="dork",status="skipped"} 1.0' in out
    assert "vantari_scan_stage_duration_seconds" not in out


def test_run_outcome_and_duration_are_recorded(monkeypatch):
    reg, orch = _patched(monkeypatch)
    start = datetime.now(UTC)
    run = ScanRun(
        tenant_id="t1",
        scan_id="s1",
        program_id="p1",
        pipeline="full",
        status=ScanStatus.SUCCESS,
        started_at=start,
        finished_at=start + timedelta(seconds=900),
    )
    orch._observe_run(run)

    out = reg.render()
    assert 'vantari_scan_run_total{pipeline="full",status="success"} 1.0' in out
    assert 'vantari_scan_run_duration_seconds_sum{pipeline="full"} 900.0' in out


def test_failed_run_is_counted_separately(monkeypatch):
    reg, orch = _patched(monkeypatch)
    run = ScanRun(
        tenant_id="t1", scan_id="s1", program_id="p1", pipeline="full", status=ScanStatus.FAILED
    )
    orch._observe_run(run)
    assert 'vantari_scan_run_total{pipeline="full",status="failed"} 1.0' in reg.render()


# -- Sentry must cover every long-running process ----------------------------
def test_every_entrypoint_initialises_sentry():
    """The API used to be the ONLY process reporting to Sentry — so every scan
    error on an unattended run was invisible. Scanning happens on the worker; the
    scheduler crashing silently stops all scanning.

    Read from source rather than importing: ``taskqueue.worker`` needs ``arq``,
    which CI doesn't install, and this assertion is about the source anyway.
    """
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    for rel in ("api/main.py", "taskqueue/worker.py", "daemon/main.py"):
        src = (root / rel).read_text()
        assert "init_sentry" in src, f"{rel} does not initialise Sentry"


def test_sentry_is_skipped_without_a_dsn():
    from core.config import Settings
    from core.observability import init_sentry

    assert init_sentry(Settings(sentry_dsn=None)) is False
