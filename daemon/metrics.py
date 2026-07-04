"""Minimal Prometheus-compatible metrics (no third-party dependency).

A tiny in-process registry with counters and gauges and a text-exposition
renderer. Kept dependency-free so the daemon and API can expose ``/metrics``
without pulling in ``prometheus_client``; can be swapped for the real library in
Phase G if richer histograms are needed.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field


@dataclass
class _Metric:
    name: str
    help: str
    kind: str  # "counter" | "gauge"
    samples: dict[tuple[tuple[str, str], ...], float] = field(default_factory=dict)


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

    def render(self) -> str:
        lines: list[str] = []
        with self._lock:
            for m in self._metrics.values():
                if m.help:
                    lines.append(f"# HELP {m.name} {m.help}")
                lines.append(f"# TYPE {m.name} {m.kind}")
                for key, val in m.samples.items():
                    if key:
                        lbl = ",".join(f'{k}="{v}"' for k, v in key)
                        lines.append(f"{m.name}{{{lbl}}} {val}")
                    else:
                        lines.append(f"{m.name} {val}")
        return "\n".join(lines) + "\n"


REGISTRY = MetricsRegistry()
