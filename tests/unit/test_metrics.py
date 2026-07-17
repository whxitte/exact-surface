"""Metrics registry (core/metrics.py) — counters, gauges, histograms, exposition."""

from __future__ import annotations

from core.metrics import MetricsRegistry


def test_counter_accumulates_per_label_set():
    r = MetricsRegistry()
    r.inc("reqs_total", help="h", decision="allowed")
    r.inc("reqs_total", decision="allowed")
    r.inc("reqs_total", decision="throttled")
    out = r.render()
    assert 'reqs_total{decision="allowed"} 2.0' in out
    assert 'reqs_total{decision="throttled"} 1.0' in out
    assert "# TYPE reqs_total counter" in out


def test_gauge_replaces_rather_than_accumulates():
    r = MetricsRegistry()
    r.set("rate_pps", 10.0)
    r.set("rate_pps", 300.0)
    assert "rate_pps 300.0" in r.render()


def test_histogram_buckets_are_cumulative():
    r = MetricsRegistry()
    r.observe("lat_seconds", 0.4, buckets=(0.5, 1, 5))
    r.observe("lat_seconds", 3.0, buckets=(0.5, 1, 5))
    out = r.render()
    # 0.4 lands in every bucket >= 0.5; 3.0 only in le=5
    assert 'lat_seconds_bucket{le="0.5"} 1.0' in out
    assert 'lat_seconds_bucket{le="1"} 1.0' in out
    assert 'lat_seconds_bucket{le="5"} 2.0' in out
    assert 'lat_seconds_bucket{le="+Inf"} 2.0' in out
    assert "lat_seconds_sum 3.4" in out
    assert "lat_seconds_count 2.0" in out
    assert "# TYPE lat_seconds histogram" in out


def test_histogram_value_beyond_the_last_bucket_still_counts():
    """An outlier must not vanish — +Inf and _count still include it."""
    r = MetricsRegistry()
    r.observe("lat_seconds", 9999.0, buckets=(1, 5))
    out = r.render()
    assert 'lat_seconds_bucket{le="5"} 0.0' in out
    assert 'lat_seconds_bucket{le="+Inf"} 1.0' in out
    assert "lat_seconds_count 1.0" in out


def test_histogram_with_labels():
    r = MetricsRegistry()
    r.observe("lat_seconds", 2.0, buckets=(1, 5), kind="finding")
    out = r.render()
    assert 'lat_seconds_bucket{kind="finding",le="5"} 1.0' in out
    assert 'lat_seconds_sum{kind="finding"} 2.0' in out


def test_registries_are_independent():
    a, b = MetricsRegistry(), MetricsRegistry()
    a.inc("x")
    assert "x" not in b.render()


def test_empty_registry_renders_cleanly():
    assert MetricsRegistry().render() == "\n"
