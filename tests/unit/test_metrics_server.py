"""The scrape path for processes that serve no other HTTP (§7 Phase G).

:class:`core.metrics.MetricsRegistry` is per-process in-memory state. Every metric
that describes scanning is emitted in the *worker*, and arq gives the worker no
HTTP server — so before this listener existed those samples were recorded and then
discarded at exit, and a dashboard built on them would have rendered empty forever.

These bind a real socket on an ephemeral port and scrape it over real HTTP: the
thing under test *is* "can Prometheus reach this", so a stubbed transport would
assert nothing worth knowing. Loopback only, no external I/O.
"""

from __future__ import annotations

import urllib.error
import urllib.request

import pytest

from core.metrics import REGISTRY
from daemon.metrics_server import start_metrics_server, stop_metrics_server


def _get(port: int, path: str) -> tuple[int, str, str]:
    """Scrape the listener the way Prometheus would. Returns (status, ctype, body)."""
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=5) as resp:
            return resp.status, resp.headers.get("Content-Type", ""), resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers.get("Content-Type", ""), exc.read().decode()


@pytest.fixture
def server():
    srv = start_metrics_server(0, host="127.0.0.1")
    assert srv is not None
    yield srv
    stop_metrics_server(srv)


def test_metrics_endpoint_renders_the_process_registry(server):
    REGISTRY.inc("vantari_test_scrape_total", help="probe")
    status, _, body = _get(server.port, "/metrics")
    assert status == 200
    assert "vantari_test_scrape_total" in body


def test_metrics_is_served_as_prometheus_text(server):
    """Prometheus refuses a body whose exposition format it cannot parse."""
    _, content_type, _ = _get(server.port, "/metrics")
    assert content_type.startswith("text/plain")
    assert "version=0.0.4" in content_type


def test_health_endpoint_responds(server):
    assert _get(server.port, "/health")[::2] == (200, "ok")


def test_unknown_path_is_404(server):
    assert _get(server.port, "/../etc/passwd")[0] == 404


def test_a_port_clash_does_not_take_the_process_down(server):
    """Metrics must never be the reason a worker fails to start — losing all
    scanning to gain a dashboard is a bad trade."""
    assert start_metrics_server(server.port, host="127.0.0.1") is None  # None, not a raise


def test_stop_tolerates_a_server_that_never_started():
    stop_metrics_server(None)  # start returned None → shutdown must not blow up
