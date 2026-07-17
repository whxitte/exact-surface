"""Expose a process's metrics registry over HTTP so Prometheus can scrape it.

:class:`core.metrics.MetricsRegistry` is plain in-memory state, so it is *per
process*. The API serves its own registry from ``GET /metrics``, but the worker
and the scheduler have no HTTP server — which meant every metric emitted where
scanning actually happens (stage outcomes, run durations, politeness decisions,
port-scan rates, alert latency) was recorded and then thrown away on exit.

This is the standard multi-process Prometheus pattern: each process exposes its
own registry and the scrape config discovers all of them. Deliberately *not* a
pushgateway — these are live counters owned by a long-running process, not a
batch job's terminal state.

Why stdlib rather than aiohttp: the endpoint serves one text page every scrape
interval, so an event loop buys nothing — and a worker's loop spends most of its
life awaiting blocking scan subprocesses, exactly when an operator most wants the
scrape to answer. On its own thread it stays responsive regardless.
``MetricsRegistry`` is already ``threading.Lock``-guarded (``render()`` included),
so reading it from that thread is safe.

Best-effort by design: metrics must never be the reason a worker fails to start.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from core.logging import logger
from core.metrics import REGISTRY

#: Prometheus rejects a body it cannot parse; this exposition version is the contract.
CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802 - stdlib's required casing
        path = self.path.split("?", 1)[0]
        if path == "/metrics":
            self._respond(200, REGISTRY.render().encode(), CONTENT_TYPE)
        elif path == "/health":
            # Lets an orchestrator liveness-probe a process that serves nothing else.
            self._respond(200, b"ok", "text/plain; charset=utf-8")
        else:
            self._respond(404, b"not found", "text/plain; charset=utf-8")

    def _respond(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args) -> None:
        """Silence stdlib's stderr access log — a scrape every 15s for days would
        drown the scan logs this process exists to produce."""


class MetricsServer:
    """A running metrics listener. Use :func:`start_metrics_server` to build one."""

    #: ``serve_forever``'s poll interval doubles as how long ``shutdown()`` blocks.
    #: The stdlib default of 0.5s is dead time on every worker restart, for a loop
    #: that is just a selector timeout.
    POLL_INTERVAL = 0.05

    def __init__(self, httpd: ThreadingHTTPServer) -> None:
        self._httpd = httpd
        self._thread = threading.Thread(
            target=lambda: httpd.serve_forever(poll_interval=self.POLL_INTERVAL),
            name="metrics-server",
            daemon=True,
        )

    @property
    def port(self) -> int:
        """The bound port — resolves the real one when 0 was requested."""
        return self._httpd.server_address[1]

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=5)


def start_metrics_server(
    port: int,
    *,
    host: str = "0.0.0.0",  # noqa: S104 - see below; the bind is required and bounded
) -> MetricsServer | None:
    """Serve ``/metrics`` on ``port``. Returns the server to stop, or None on failure.

    On binding all interfaces (ruff S104): Prometheus scrapes this from another
    container, so loopback would make it unreachable and the metrics unscrapeable —
    the whole point of the listener. The exposure is bounded deliberately: the
    compose file publishes no host port for it, the handler serves two read-only
    routes and nothing mutating, and no metric carries a tenant label (which is
    also why cardinality stays flat). The reachability boundary is the container
    network. If you run the worker directly on a shared host, pass
    ``host="127.0.0.1"`` and scrape it locally.
    """
    try:
        httpd = ThreadingHTTPServer((host, port), _Handler)
    except OSError as exc:
        # A port clash must not take the process down — that would trade all
        # scanning for a dashboard.
        logger.warning("metrics server could not bind {}:{} — {}", host, port, exc)
        return None
    server = MetricsServer(httpd)
    server.start()
    logger.info("metrics server listening on {}:{}/metrics", host, server.port)
    return server


def stop_metrics_server(server: MetricsServer | None) -> None:
    if server is not None:
        server.stop()
