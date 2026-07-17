"""In-process Prometheus-compatible metrics registry (counters, gauges, histograms).

Lives in ``core`` deliberately — see ADR-0010. It is pure in-memory state with no
I/O, and it is consumed by every layer (``core.ratelimit`` needs to count throttle
decisions, ``pipelines`` publish scan rates, ``api`` renders ``/metrics``). Putting
it under ``daemon`` forced ``core → daemon`` imports, which inverts the dependency
direction, so the rate limiter simply went uninstrumented instead.

Dependency-free on purpose: no ``prometheus_client``. Swap it if/when the
exposition needs features this doesn't cover (exemplars, native histograms).
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field

#: Default histogram buckets (seconds) for latency work — spans a fast in-process
#: op through the §15 alert-latency targets (<15 min) and well past them, so a
#: badly-lagging pipeline is still visible rather than clipped into +Inf.
LATENCY_BUCKETS: tuple[float, ...] = (
    0.1,
    0.5,
    1,
    5,
    15,
    60,
    300,
    900,
    1800,
    3600,
    21600,
    86400,
)


@dataclass
class _Metric:
    name: str
    help: str
    kind: str  # "counter" | "gauge" | "histogram"
    samples: dict[tuple[tuple[str, str], ...], float] = field(default_factory=dict)
    #: histogram only: labels -> {bucket_upper_bound: cumulative_count}
    buckets: dict[tuple[tuple[str, str], ...], dict[float, float]] = field(default_factory=dict)
    #: histogram only: labels -> (sum, count)
    totals: dict[tuple[tuple[str, str], ...], tuple[float, float]] = field(default_factory=dict)
    bounds: tuple[float, ...] = ()


class MetricsRegistry:
    def __init__(self) -> None:
        self._metrics: dict[str, _Metric] = {}
        self._lock = threading.Lock()

    def _get(self, name: str, help: str, kind: str) -> _Metric:
        m = self._metrics.get(name)
        if m is None:
            m = _Metric(name, help, kind)
            self._metrics[name] = m
        return m

    def inc(self, name: str, value: float = 1.0, help: str = "", **labels: str) -> None:
        key = tuple(sorted(labels.items()))
        with self._lock:
            m = self._get(name, help, "counter")
            m.samples[key] = m.samples.get(key, 0.0) + value

    def set(self, name: str, value: float, help: str = "", **labels: str) -> None:
        key = tuple(sorted(labels.items()))
        with self._lock:
            m = self._get(name, help, "gauge")
            m.samples[key] = value

    def observe(
        self,
        name: str,
        value: float,
        help: str = "",
        buckets: tuple[float, ...] = LATENCY_BUCKETS,
        **labels: str,
    ) -> None:
        """Record *value* into a histogram. Buckets are cumulative (Prometheus-style)."""
        key = tuple(sorted(labels.items()))
        with self._lock:
            m = self._get(name, help, "histogram")
            if not m.bounds:
                m.bounds = tuple(sorted(buckets))
            counts = m.buckets.setdefault(key, dict.fromkeys(m.bounds, 0.0))
            for bound in m.bounds:
                if value <= bound:
                    counts[bound] += 1
            total_sum, total_count = m.totals.get(key, (0.0, 0.0))
            m.totals[key] = (total_sum + value, total_count + 1)

    def _render_histogram(self, m: _Metric, lines: list[str]) -> None:
        for key, counts in m.buckets.items():
            base = dict(key)
            for bound in m.bounds:
                labels = {**base, "le": _fmt(bound)}
                lines.append(f"{m.name}_bucket{{{_labels(labels)}}} {counts[bound]}")
            total_sum, total_count = m.totals[key]
            lines.append(f"{m.name}_bucket{{{_labels({**base, 'le': '+Inf'})}}} {total_count}")
            suffix = f"{{{_labels(base)}}}" if base else ""
            lines.append(f"{m.name}_sum{suffix} {total_sum}")
            lines.append(f"{m.name}_count{suffix} {total_count}")

    def render(self) -> str:
        lines: list[str] = []
        with self._lock:
            for m in self._metrics.values():
                if m.help:
                    lines.append(f"# HELP {m.name} {m.help}")
                lines.append(f"# TYPE {m.name} {m.kind}")
                if m.kind == "histogram":
                    self._render_histogram(m, lines)
                    continue
                for key, val in m.samples.items():
                    if key:
                        lines.append(f"{m.name}{{{_labels(dict(key))}}} {val}")
                    else:
                        lines.append(f"{m.name} {val}")
        return "\n".join(lines) + "\n"


def _fmt(bound: float) -> str:
    return str(int(bound)) if float(bound).is_integer() else str(bound)


def _labels(labels: dict) -> str:
    return ",".join(f'{k}="{v}"' for k, v in labels.items())


REGISTRY = MetricsRegistry()
