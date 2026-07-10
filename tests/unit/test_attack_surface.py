"""Attack-surface change analytics: present-over-time, resolved detection, deltas."""

from __future__ import annotations

from datetime import UTC, datetime

from core.attack_surface import compute_attack_surface

T0 = datetime(2026, 7, 1, 12, 0, tzinfo=UTC)  # first scan
T1 = datetime(2026, 7, 2, 12, 0, tzinfo=UTC)  # second scan
T2 = datetime(2026, 7, 3, 12, 0, tzinfo=UTC)  # third (latest) scan


def _item(fs, ls, **extra):
    return {"first_seen": fs, "last_seen": ls, **extra}


def _compute(items_by_type, points, reference):
    return compute_attack_surface(
        items_by_type=items_by_type, scan_points=points, reference=reference, now=T2
    )


def test_resolved_when_not_seen_since_latest_scan():
    # a port open at T0/T1 but not re-seen by the latest scan (ref=T2) → resolved
    ports = [
        _item(T0, T2, ip="1.1.1.1", port=443, protocol="tcp"),  # still open
        _item(T0, T1, ip="1.1.1.1", port=8080, protocol="tcp"),  # closed since
    ]
    out = _compute({"ports": ports}, [T0, T1, T2], reference=T2)
    assert out["current"]["ports"]["total"] == 1  # only the still-open port is active
    assert out["change"]["ports"]["resolved"] == 1  # the 8080 port closed since T1


def test_opened_since_previous_scan_counts_as_new():
    endpoints = [
        _item(T0, T2, url="https://a.com/"),  # old, still present
        _item(T2, T2, url="https://a.com/new"),  # appeared at the latest scan
    ]
    out = _compute({"endpoints": endpoints}, [T0, T1, T2], reference=T2)
    assert out["change"]["endpoints"]["opened"] == 1
    assert out["current"]["endpoints"]["total"] == 2


def test_series_tracks_surface_size_over_time():
    endpoints = [
        _item(T0, T2, url="https://a.com/1"),  # present at T0,T1,T2
        _item(T1, T2, url="https://a.com/2"),  # present at T1,T2
        _item(T0, T0, url="https://a.com/gone"),  # only present at T0
    ]
    out = _compute({"endpoints": endpoints}, [T0, T1, T2], reference=T2)
    by_at = {row["at"]: row["endpoints"] for row in out["series"]}
    assert by_at[T0.isoformat()] == 2  # /1 and /gone
    assert by_at[T1.isoformat()] == 2  # /1 and /2
    assert by_at[T2.isoformat()] == 2  # /1 and /2 (gone dropped off)


def test_findings_broken_down_by_severity_and_net_change():
    findings = [
        _item(T0, T2, name="Old low", severity="low"),  # active
        _item(T2, T2, name="New high", severity="high"),  # opened this scan
        _item(T0, T1, name="Fixed medium", severity="medium"),  # resolved since T1
    ]
    out = _compute({"findings": findings}, [T0, T1, T2], reference=T2)
    cur = out["current"]["findings"]
    assert cur["total"] == 2 and cur["high"] == 1 and cur["low"] == 1
    assert out["change"]["findings"] == {"opened": 1, "resolved": 1}
    # a recent change log with both an opened and a resolved event
    kinds = {(e["kind"], e["type"]) for e in out["recent"]}
    assert ("opened", "finding") in kinds and ("resolved", "finding") in kinds


def test_no_scans_yet_everything_active_no_resolved():
    out = _compute({"assets": [_item(T0, T0, hostname="a.com")]}, [], reference=None)
    assert out["current"]["assets"]["total"] == 1
    assert out["change"]["assets"]["resolved"] == 0
    assert out["series"] == [] and out["scan_count"] == 0
