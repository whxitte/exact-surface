"""Evidence-based gone-detection: only a full-coverage re-run declares an item gone."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from core.liveness import (
    annotate_gone,
    const_phase,
    endpoint_phase,
    finding_phase,
    phase_reference_starts,
)

T0 = datetime(2026, 7, 1, tzinfo=UTC)  # first full scan
T1 = T0 + timedelta(hours=6)  # a cascade run (partial)
T2 = T0 + timedelta(days=1)  # second full scan


def _full_run(start, stages):
    return {
        "pipeline": "full",
        "started_at": start,
        "targets": [],
        "stages": [{"name": n, "status": s, "started_at": start} for n, s in stages],
    }


def _phase_run(pipeline, start, *, status="success", targets=()):
    return {"pipeline": pipeline, "started_at": start, "status": status, "targets": list(targets)}


def test_reference_ignores_cascade_runs():
    runs = [
        _full_run(T0, [("scan", "success")]),
        _phase_run("scan", T1, targets=["new.acme.com"]),  # cascade — must be ignored
    ]
    refs = phase_reference_starts(runs)
    assert refs["scan"] == T0  # cascade at T1 did NOT advance the reference


def test_scheduled_single_phase_run_is_a_reference():
    refs = phase_reference_starts([_phase_run("port_scan", T2)])
    assert refs["port_scan"] == T2


def test_partial_run_does_not_resolve_untouched_findings():
    # The reported bug: an initial full scan, then a cascade scan bumps one finding's
    # last_seen — the others must NOT be marked resolved.
    refs = phase_reference_starts(
        [_full_run(T0, [("scan", "success")]), _phase_run("scan", T1, targets=["new"])]
    )
    docs = [
        {"module": "nuclei", "last_seen": T0},  # from the full scan, untouched since
        {"module": "nuclei", "last_seen": T1},  # re-found by the cascade
    ]
    annotate_gone(docs, refs, finding_phase)
    assert docs[0]["gone"] is False and docs[1]["gone"] is False


def test_second_full_run_marks_the_missing_one_gone():
    refs = phase_reference_starts(
        [_full_run(T0, [("scan", "success")]), _full_run(T2, [("scan", "success")])]
    )
    docs = [
        {"module": "nuclei", "last_seen": T0},  # not re-observed by the T2 full run → gone
        {"module": "nuclei", "last_seen": T2},  # re-observed at T2 → live
    ]
    annotate_gone(docs, refs, finding_phase)
    assert docs[0]["gone"] is True and docs[1]["gone"] is False


def test_flaky_empty_run_marks_nothing_gone():
    # A later full run whose scan stage "succeeded" but observed nothing (e.g. the tool
    # failed): no peer advanced to T2, so nothing may flip to gone.
    refs = phase_reference_starts(
        [_full_run(T0, [("scan", "success")]), _full_run(T2, [("scan", "success")])]
    )
    docs = [{"module": "nuclei", "last_seen": T0}, {"module": "nuclei", "last_seen": T0}]
    annotate_gone(docs, refs, finding_phase)
    assert all(d["gone"] is False for d in docs)  # ref T2 > phase_max T0 → not applied


def test_endpoint_source_judged_against_own_phase():
    # probe re-ran (roots only); a feroxbuster path must NOT be judged against it.
    refs = phase_reference_starts([_phase_run("probe", T2)])
    docs = [
        {"source": "feroxbuster", "last_seen": T0},  # content_discovery hasn't re-run
        {"source": "probe", "last_seen": T0},  # probe re-ran at T2 and missed it → gone
    ]
    annotate_gone(docs, refs, endpoint_phase)
    assert docs[0]["gone"] is False  # no content_discovery reference
    # probe ref exists but phase_max(probe)=T0 < T2 → run observed nothing → not gone
    assert docs[1]["gone"] is False


def test_port_gone_after_full_coverage_rescan():
    refs = phase_reference_starts([_phase_run("port_scan", T0), _phase_run("port_scan", T2)])
    docs = [
        {"last_seen": T0},  # closed — not seen at T2
        {"last_seen": T2},  # still open at T2
    ]
    annotate_gone(docs, refs, const_phase("port_scan"))
    assert docs[0]["gone"] is True and docs[1]["gone"] is False
